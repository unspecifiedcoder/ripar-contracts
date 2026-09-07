"""
End-to-end escrow flows, wired in-process.

`algorand-python-testing` 1.1.0 does not implement `arc4.abi_call`, so the three
registries are connected by monkeypatching it: a call to the identity app runs
the REAL `IdentityRegistry.agent_address`, and a call to the reputation app runs
the REAL `ReputationRegistry.record_validation` with `caller_application_id` set
to the validation app — exactly what the AVM does. No contract logic is mocked.

The harness is ATOMIC: algopy-testing does not roll back box or global writes
when a method raises, but the AVM does. `_call` snapshots all three apps' boxes
and global state and restores them if the call reverts, so a failed call leaves
the ledger exactly as the chain would — without this, a revert could leave a
half-applied write and give an attack a false shape.

These tests prove the 2026-09 audit fixes, INCLUDING the SPLIT redesign that
replaced an earlier fix whose own flaw a red-team found (a "client fallback
judge" merely moved the free option from the worker to the client). The design
now: whoever initiates the pairing names a fallback judge, the other side
consents by committing, and if both judges stay silent the escrow splits 50/50 so
neither side wins by default.

The emulator does not model the box min_balance delta, so the exact `mbr.amount`
half of the storage guard is proven on chain, not here.
"""

import copy

import algopy.arc4 as _arc4mod
import pytest
from algopy import Bytes, UInt64, arc4
from algopy_testing import algopy_testing_context

from contracts.identity_registry import IdentityRegistry
from contracts.reputation_registry import ReputationRegistry
from contracts.validation_registry import ValidationRegistry

USDC = 10_458_941
H = arc4.DynamicBytes(Bytes(b"\x11" * 32))
MBR = 400_000
VALIDATED, DISPUTED, SPLIT = 3, 4, 6


class World:
    def __init__(self, ctx, dispute_window=300):
        self.ctx = ctx
        self.identity = IdentityRegistry()
        self.reputation = ReputationRegistry()
        self.validation = ValidationRegistry()
        self.identity_app = ctx.ledger.get_app(self.identity)
        self.reputation_app = ctx.ledger.get_app(self.reputation)
        self.validation_app = ctx.ledger.get_app(self.validation)
        self.usdc = ctx.any.asset(asset_id=USDC, total=10**18, decimals=6)
        self.creator = ctx.default_sender
        with ctx.txn.create_group(active_txn_overrides={"sender": self.creator}):
            self.reputation.bootstrap(arc4.UInt64(self.identity_app.id), arc4.UInt64(USDC))
        with ctx.txn.create_group(active_txn_overrides={"sender": self.creator}):
            self.validation.bootstrap(
                arc4.UInt64(self.identity_app.id),
                arc4.UInt64(self.reputation_app.id),
                arc4.UInt64(USDC),
                arc4.UInt64(dispute_window),
            )
        with ctx.txn.create_group(active_txn_overrides={"sender": self.creator}):
            self.reputation.set_validation_app(arc4.UInt64(self.validation_app.id))
        self.rep_broken = False
        self.now = 1_000_000
        self.set_time(self.now)

    # --- clock -------------------------------------------------------------
    def set_time(self, t):
        self.now = t
        self.ctx.ledger.patch_global_fields(latest_timestamp=UInt64(t))

    def advance(self, secs):
        self.set_time(self.now + secs)

    # --- abi_call shim -----------------------------------------------------
    def abi_call(self, method, *args, app_id, **kw):
        app_id = int(app_id)
        if app_id == self.identity_app.id:
            assert method.startswith("agent_address")
            return IdentityRegistry.agent_address.__wrapped__(self.identity, args[0]), None
        if app_id == self.reputation_app.id:
            assert method.startswith("record_validation")
            if self.rep_broken:
                raise AssertionError("box_put: insufficient balance (reputation app MBR exhausted)")
            self.ctx.ledger.patch_global_fields(
                caller_application_id=UInt64(int(self.validation_app.id))
            )
            try:
                return (
                    ReputationRegistry.record_validation.__wrapped__(
                        self.reputation, args[0], args[1], args[2]
                    ),
                    None,
                )
            finally:
                self.ctx.ledger.patch_global_fields(caller_application_id=UInt64(0))
        raise AssertionError(f"unexpected abi_call to {app_id}")

    # --- atomic call -------------------------------------------------------
    def _snapshot(self):
        snap = {}
        for app in (self.identity_app, self.reputation_app, self.validation_app):
            d = self.ctx.ledger._get_app_data(app)
            snap[app.id] = (copy.deepcopy(d.boxes), copy.deepcopy(d.global_state))
        return snap

    def _restore(self, snap):
        for app in (self.identity_app, self.reputation_app, self.validation_app):
            d = self.ctx.ledger._get_app_data(app)
            boxes, gs = snap[app.id]
            d.boxes.clear(); d.boxes.update(boxes)
            d.global_state.clear(); d.global_state.update(gs)

    def _atomic(self, fn):
        snap = self._snapshot()
        try:
            return fn()
        except Exception:
            self._restore(snap)
            raise

    def call(self, sender, fn, *args):
        def run():
            with self.ctx.txn.create_group(active_txn_overrides={"sender": sender}):
                return fn(*args)
        return self._atomic(run)

    def _grouped(self, sender, txns, fn):
        def run():
            call = self.ctx.any.txn.application_call(sender=sender, app_id=self.validation_app)
            with self.ctx.txn.create_group(gtxns=[*txns, call], active_txn_index=len(txns)):
                return fn()
        return self._atomic(run)

    def _pay(self, sender, receiver, amount):
        return self.ctx.any.txn.payment(sender=sender, receiver=receiver, amount=UInt64(amount))

    # --- helpers -----------------------------------------------------------
    def register(self, acct, domain):
        def run():
            pay = self._pay(acct, self.identity_app.address, MBR)
            call = self.ctx.any.txn.application_call(sender=acct, app_id=self.identity_app)
            with self.ctx.txn.create_group(gtxns=[pay, call], active_txn_index=1):
                return self.identity.new_agent(pay, arc4.String(domain)).native
        return self._atomic(run)

    def deregister(self, acct, agent_id):
        return self.call(acct, self.identity.deregister_agent, arc4.UInt64(agent_id))

    def post_job(self, client, budget, validator_id=0):
        pay = self._pay(client, self.validation_app.address, MBR)
        return self._grouped(
            client, [pay],
            lambda: self.validation.post_job(pay, H, arc4.UInt64(budget), arc4.UInt64(validator_id)),
        ).native

    def assign(self, client, jid, worker, fallback=0):
        return self.call(
            client, self.validation.assign_job,
            arc4.UInt64(jid), arc4.UInt64(worker), arc4.UInt64(fallback),
        )

    def bid(self, bidder, jid, agent_id, price, fallback=0):
        pay = self._pay(bidder, self.validation_app.address, MBR)
        return self._grouped(
            bidder, [pay],
            lambda: self.validation.place_bid(
                pay, arc4.UInt64(jid), arc4.UInt64(agent_id), arc4.UInt64(price), H, arc4.UInt64(fallback)
            ),
        )

    def accept(self, client, jid, agent_id, price):
        return self.call(
            client, self.validation.accept_bid,
            arc4.UInt64(jid), arc4.UInt64(agent_id), arc4.UInt64(price),
        )

    def fund(self, client, jid, amount):
        mbr = self._pay(client, self.validation_app.address, MBR)
        axfer = self.ctx.any.txn.asset_transfer(
            sender=client, asset_receiver=self.validation_app.address,
            xfer_asset=self.usdc, asset_amount=UInt64(amount),
        )
        return self._grouped(
            client, [mbr, axfer],
            lambda: self.validation.fund_job(mbr, axfer, arc4.UInt64(jid)),
        ).native

    def submit(self, worker, jid):
        pay = self._pay(worker, self.validation_app.address, MBR)
        return self._grouped(
            worker, [pay], lambda: self.validation.submit_result(pay, arc4.UInt64(jid), H)
        )

    def judge(self, sender, jid, passed, as_validator):
        return self.call(
            sender, self.validation.validation_response,
            arc4.UInt64(jid), arc4.Bool(passed), arc4.UInt64(as_validator),
        )

    def status(self, jid):
        return self.call(self.creator, self.validation.get_job, arc4.UInt64(jid)).status.native

    def itxns(self):
        out = []
        for grp in self.ctx.txn.last_group.itxn_groups:
            for it in grp:
                try:
                    out.append((it.asset_receiver, int(it.asset_amount)))
                except Exception:  # noqa: BLE001
                    pass
        return out


@pytest.fixture()
def ctx():
    with algopy_testing_context() as c:
        yield c


@pytest.fixture()
def world(ctx, monkeypatch):
    w = World(ctx)

    class Shim:
        def __getitem__(self, _t):
            return self

        def __call__(self, method, *args, **kw):
            return w.abi_call(method, *args, **kw)

    monkeypatch.setattr(_arc4mod, "abi_call", Shim())
    monkeypatch.setattr(arc4, "abi_call", Shim())
    return w


def _job(world, validator_id=0, budget=1_000_000, escrow=None, fallback=0):
    ctx = world.ctx
    client = ctx.any.account()
    w_acct = ctx.any.account()
    w = world.register(w_acct, "worker.example")
    jid = world.post_job(client, budget, validator_id)
    world.assign(client, jid, w, fallback)
    if escrow:
        world.fund(client, jid, escrow)
    return client, w_acct, w, jid


# --- R-4: escrow capped at budget, excess refunded to client ----------------


def test_R4_release_caps_at_budget_and_refunds_excess_to_client(world):
    ctx = world.ctx
    client = ctx.any.account()
    w_acct = ctx.any.account()
    w = world.register(w_acct, "w.example")
    jid = world.post_job(client, 1_000_000)
    world.fund(client, jid, 1_000_000)
    world.bid(w_acct, jid, w, 400_000)
    world.accept(client, jid, w, 400_000)
    world.submit(w_acct, jid)
    world.judge(client, jid, True, 0)  # no validator named -> client judges

    world.advance(301)
    paid = world.call(ctx.any.account(), world.validation.release_escrow, arc4.UInt64(jid)).native
    xfers = world.itxns()
    assert paid == 400_000
    assert (w_acct, 400_000) in xfers
    assert (client, 600_000) in xfers


def test_R4_fund_job_refuses_to_exceed_the_budget(world):
    client, w_acct, w, jid = _job(world, budget=500_000)
    with pytest.raises(Exception, match="cannot exceed the agreed budget"):
        world.fund(client, jid, 500_001)


# --- the SPLIT: double silence pays neither side in full --------------------


def test_SPLIT_double_silence_splits_escrow_50_50(world):
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    fb_acct = ctx.any.account()
    fb = world.register(fb_acct, "fallback.example")
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000, fallback=fb)
    world.submit(w_acct, jid)

    world.advance(301)  # validator window
    with pytest.raises(Exception, match="the validator, then the fallback, still have time"):
        world.call(ctx.any.account(), world.validation.expire_verdict, arc4.UInt64(jid))
    world.advance(301)  # fallback window
    world.call(ctx.any.account(), world.validation.expire_verdict, arc4.UInt64(jid))
    assert world.status(jid) == SPLIT

    assert world.call(ctx.any.account(), world.validation.settle_split, arc4.UInt64(jid)).native == 500_000
    assert (w_acct, 500_000) in world.itxns()
    assert world.call(ctx.any.account(), world.validation.claim_split_refund, arc4.UInt64(jid)).native == 500_000
    assert (client, 500_000) in world.itxns()


def test_SPLIT_client_half_survives_a_departed_worker(world):
    """A worker who vanishes strands only their OWN half; the client's half is in
    a separate box that never resolves the worker."""
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000)
    world.submit(w_acct, jid)
    world.deregister(w_acct, w)
    world.advance(602)
    world.call(ctx.any.account(), world.validation.expire_verdict, arc4.UInt64(jid))
    with pytest.raises(Exception, match="unknown agent"):
        world.call(client, world.validation.settle_split, arc4.UInt64(jid))  # worker's half stranded (self-inflicted)
    assert world.call(ctx.any.account(), world.validation.claim_split_refund, arc4.UInt64(jid)).native == 500_000
    assert (client, 500_000) in world.itxns()


# --- the fallback judge, and the A1 attack that must now fail ---------------


def test_A1_client_can_no_longer_rug_a_delivering_worker(world):
    """The red-team's A1: with the old client-fallback the client could reject
    delivered work once the validator was silent. Now the client is NOT a judge
    on a validator-named job, at any time."""
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000)
    world.submit(w_acct, jid)
    world.advance(1000)  # validator long silent
    with pytest.raises(Exception, match="only the named validator may judge, or the fallback"):
        world.judge(client, jid, False, 0)
    with pytest.raises(Exception, match="you do not control that validator"):
        world.judge(client, jid, False, v)


def test_fallback_judges_only_after_the_validator_window(world):
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    fb_acct = ctx.any.account()
    fb = world.register(fb_acct, "fallback.example")
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000, fallback=fb)
    world.submit(w_acct, jid)

    with pytest.raises(Exception, match="only the named validator may judge, or the fallback"):
        world.judge(fb_acct, jid, True, fb)  # too early
    world.advance(301)
    world.judge(fb_acct, jid, True, fb)  # validator silent -> fallback may act
    assert world.status(jid) == VALIDATED
    assert world.call(client, world.validation.release_escrow, arc4.UInt64(jid)).native == 1_000_000


def test_dead_validator_does_not_strand_the_job(world):
    """B/A1b class: a validator that deregisters no longer locks the job — the
    fallback path never resolves the dead primary."""
    ctx = world.ctx
    v_acct = ctx.any.account()
    v = world.register(v_acct, "v.example")
    fb_acct = ctx.any.account()
    fb = world.register(fb_acct, "fallback.example")
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000, fallback=fb)
    world.submit(w_acct, jid)
    world.deregister(v_acct, v)
    world.advance(301)
    world.judge(fb_acct, jid, True, fb)
    assert world.status(jid) == VALIDATED


def test_fallback_may_not_be_a_party_or_the_validator(world):
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    client = ctx.any.account()
    w_acct = ctx.any.account()
    w = world.register(w_acct, "worker.example")
    jid = world.post_job(client, 1_000_000, v)
    with pytest.raises(Exception, match="the fallback must differ from the validator"):
        world.assign(client, jid, w, fallback=v)
    with pytest.raises(Exception, match="the worker cannot be their own fallback"):
        world.assign(client, jid, w, fallback=w)


# --- R-2 / B2: verdict finality does not depend on the reputation app -------


def test_B2_breaking_reputation_cannot_block_or_flip_a_verdict(world):
    """The red-team's B2 lever: drain the reputation app so record_validation
    reverts. validation_response no longer touches reputation, so the verdict
    lands anyway; only the separate sync fails, and it is retryable."""
    ctx = world.ctx
    v_acct = ctx.any.account()
    v = world.register(v_acct, "v.example")
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000)
    world.submit(w_acct, jid)

    world.rep_broken = True
    world.judge(v_acct, jid, False, v)  # honest fail lands despite broken reputation
    assert world.status(jid) == DISPUTED
    mbr = world._pay(client, world.reputation_app.address, 37_000)
    with pytest.raises(Exception, match="insufficient balance"):
        world._grouped(client, [mbr], lambda: world.validation.record_job_verdict(mbr, arc4.UInt64(jid)))
    assert world.call(w_acct, world.validation.refund_escrow, arc4.UInt64(jid)).native == 1_000_000

    world.rep_broken = False
    mbr2 = world._pay(client, world.reputation_app.address, 37_000)
    world._grouped(client, [mbr2], lambda: world.validation.record_job_verdict(mbr2, arc4.UInt64(jid)))
    sc = world.call(client, world.reputation.get_score, arc4.UInt64(w))
    assert sc.disputed.native == 1 and sc.validated.native == 0


def test_R2_refund_takes_no_fee_but_settlement_does(world):
    ctx = world.ctx
    treasury = ctx.any.account(opted_asset_balances={world.usdc.id: UInt64(0)})
    world.call(world.creator, world.validation.set_fee, arc4.UInt64(250), arc4.Address(treasury))
    # refund path: no fee
    client = ctx.any.account()
    jid = world.post_job(client, 1_000_000)
    world.fund(client, jid, 1_000_000)
    world.call(client, world.validation.cancel_job, arc4.UInt64(jid))
    assert world.call(ctx.any.account(), world.validation.refund_escrow, arc4.UInt64(jid)).native == 1_000_000
    assert (treasury, 25_000) not in world.itxns()
    # settlement path: fee applies
    client2, w_acct, w, jid2 = _job(world, escrow=1_000_000)
    world.submit(w_acct, jid2)
    world.judge(client2, jid2, True, 0)
    assert world.call(client2, world.validation.release_escrow, arc4.UInt64(jid2)).native == 975_000
    assert (treasury, 25_000) in world.itxns()


# --- R-8: reclaim a validated escrow stranded by a departed worker ----------


def test_R8_client_reclaims_stranded_validated_escrow(world):
    ctx = world.ctx
    client, w_acct, w, jid = _job(world, escrow=1_000_000)
    world.submit(w_acct, jid)
    world.judge(client, jid, True, 0)
    world.deregister(w_acct, w)
    with pytest.raises(Exception, match="unknown agent"):
        world.call(client, world.validation.release_escrow, arc4.UInt64(jid))
    world.advance(301)
    with pytest.raises(Exception, match="still has time to be paid"):
        world.call(client, world.validation.reclaim_stranded, arc4.UInt64(jid))
    world.advance(4 * 300)
    assert world.call(client, world.validation.reclaim_stranded, arc4.UInt64(jid)).native == 1_000_000
    assert (client, 1_000_000) in world.itxns()


# --- F5: bid terms are pinned at accept ------------------------------------


def test_F5_bid_price_and_validator_are_pinned_at_accept(world):
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    client = ctx.any.account()
    b_acct = ctx.any.account()
    b = world.register(b_acct, "bidder.example")
    jid = world.post_job(client, 1000, v)
    world.bid(b_acct, jid, b, 400)
    world.bid(b_acct, jid, b, 10**9)  # bidder raises the price
    with pytest.raises(Exception, match="the bid changed since you read it"):
        world.accept(client, jid, b, 400)


# --- split halves cannot be double- or cross-claimed ------------------------


def test_split_halves_are_each_claimable_once(world):
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    client, w_acct, w, jid = _job(world, validator_id=v, budget=1_000_001, escrow=1_000_001)
    world.submit(w_acct, jid)
    world.advance(602)
    world.call(ctx.any.account(), world.validation.expire_verdict, arc4.UInt64(jid))
    assert world.call(ctx.any.account(), world.validation.settle_split, arc4.UInt64(jid)).native == 500_000
    assert world.call(ctx.any.account(), world.validation.claim_split_refund, arc4.UInt64(jid)).native == 500_001  # odd unit to client
    with pytest.raises(Exception, match="nothing is escrowed"):
        world.call(client, world.validation.settle_split, arc4.UInt64(jid))
    with pytest.raises(Exception, match="nothing to refund"):
        world.call(client, world.validation.claim_split_refund, arc4.UInt64(jid))


# --- C1: the acknowledged residual (documented, not a regression) -----------


def test_C1_worker_puppet_fallback_is_the_known_residual(world):
    """HONEST residual: a worker can name a second agent it controls as the
    fallback. On chain it is indistinguishable from an independent judge, so the
    contract cannot forbid it — only make it visible before the client commits.
    This test documents that it still 'works', which is why the fix is informed
    consent (the fallback is a visible bid/job field) plus, if desired, a
    protocol arbiter — a deployment policy choice, not a code guard."""
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    puppet_acct = ctx.any.account()
    puppet = world.register(puppet_acct, "puppet.example")  # a second key, same operator
    # client can SEE the fallback is 'puppet' before accepting (it's the job field)
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000, fallback=puppet)
    world.submit(w_acct, jid)
    world.advance(301)
    world.judge(puppet_acct, jid, True, puppet)
    assert world.status(jid) == VALIDATED


# --- the protocol arbiter follow-up: closes C1 for deployments that opt in ----


def test_arbiter_is_creator_only(world):
    ctx = world.ctx
    a = world.register(ctx.any.account(), "arbiter.example")
    with pytest.raises(Exception, match="only the creator may set the arbiter"):
        world.call(ctx.any.account(), world.validation.set_arbiter, arc4.UInt64(a))
    world.call(world.creator, world.validation.set_arbiter, arc4.UInt64(a))
    assert world.call(world.creator, world.validation.get_arbiter).native == a


def test_arbiter_supersedes_a_puppet_fallback_and_closes_C1(world):
    """With an arbiter set, a worker's own puppet fallback can no longer act — the
    arbiter is the second judge for every job, so the C1 residual is closed for
    deployments that opt in. The arbiter disputes the garbage; the client refunds."""
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    arb_acct = ctx.any.account()
    arb = world.register(arb_acct, "arbiter.example")
    world.call(world.creator, world.validation.set_arbiter, arc4.UInt64(arb))

    puppet_acct = ctx.any.account()
    puppet = world.register(puppet_acct, "puppet.example")
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000, fallback=puppet)
    world.submit(w_acct, jid)
    world.advance(301)  # validator silent

    # the worker's puppet fallback is now powerless
    with pytest.raises(Exception, match="only the named validator may judge, or the fallback/arbiter"):
        world.judge(puppet_acct, jid, True, puppet)
    # only the arbiter may act as the second judge, and it rejects the garbage
    world.judge(arb_acct, jid, False, arb)
    assert world.status(jid) == DISPUTED
    assert world.call(client, world.validation.refund_escrow, arc4.UInt64(jid)).native == 1_000_000


def test_arbiter_still_falls_back_to_split_if_even_it_is_silent(world):
    ctx = world.ctx
    v = world.register(ctx.any.account(), "v.example")
    arb = world.register(ctx.any.account(), "arbiter.example")
    world.call(world.creator, world.validation.set_arbiter, arc4.UInt64(arb))
    client, w_acct, w, jid = _job(world, validator_id=v, escrow=1_000_000)
    world.submit(w_acct, jid)
    world.advance(602)  # validator and arbiter both silent
    world.call(ctx.any.account(), world.validation.expire_verdict, arc4.UInt64(jid))
    assert world.status(jid) == SPLIT
