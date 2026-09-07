"""
End-to-end escrow flows, wired in-process.

`algorand-python-testing` 1.1.0 does not implement `arc4.abi_call`, so the three
registries are connected by monkeypatching it: a call to the identity app runs
the REAL `IdentityRegistry.agent_address`, and a call to the reputation app runs
the REAL `ReputationRegistry.record_validation` with `caller_application_id` set
to the validation app — exactly what the AVM does. No contract logic is mocked.

The technique is borrowed from the second-opinion audit pass. These tests prove
the 2026-09 audit FIXES actually execute, which the window/bootstrap unit tests
cannot reach:

  * R-4  escrow is capped at the budget and the excess refunded to the client
  * R-F1 the client is a fallback judge once the validator's window passes, and
         expire_verdict waits a second window
  * R-8  a client can reclaim a validated job stranded by an unpayable worker
  * R-2  refunds take no protocol fee (charge_fee=False)
  * R-3  validation_response records the verdict WITHOUT touching the reputation
         app, so a starved reputation app can never block a judgement

The box minimum-balance delta is not modelled by the emulator, so the exact
`mbr.amount` half of the storage guard is proven on chain, not here; every mbr
payment below just satisfies the receiver/sender checks.
"""

import algopy.arc4 as _arc4mod
import pytest
from algopy import Bytes, Global, UInt64, arc4
from algopy_testing import algopy_testing_context

from contracts.identity_registry import IdentityRegistry
from contracts.reputation_registry import ReputationRegistry
from contracts.validation_registry import ValidationRegistry

USDC = 10_458_941
H = arc4.DynamicBytes(Bytes(b"\x11" * 32))
MBR = 400_000  # a safe over-estimate; the emulator does not move min_balance


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
        self.now = 1_000_000
        self.set_time(self.now)

    # --- clock -------------------------------------------------------------
    def set_time(self, t):
        self.now = t
        self.ctx.ledger.patch_global_fields(latest_timestamp=UInt64(t))

    def advance(self, secs):
        self.set_time(self.now + secs)

    # --- abi_call shim (real callee bodies) --------------------------------
    def abi_call(self, method, *args, app_id, **kw):
        app_id = int(app_id)
        if app_id == self.identity_app.id:
            assert method.startswith("agent_address")
            return IdentityRegistry.agent_address.__wrapped__(self.identity, args[0]), None
        if app_id == self.reputation_app.id:
            assert method.startswith("record_validation")
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

    # --- helpers -----------------------------------------------------------
    def _pay(self, sender, receiver, amount):
        return self.ctx.any.txn.payment(sender=sender, receiver=receiver, amount=UInt64(amount))

    def _grouped(self, sender, txns, fn):
        call = self.ctx.any.txn.application_call(sender=sender, app_id=self.validation_app)
        with self.ctx.txn.create_group(gtxns=[*txns, call], active_txn_index=len(txns)):
            return fn()

    def register(self, acct, domain):
        pay = self._pay(acct, self.identity_app.address, MBR)
        call = self.ctx.any.txn.application_call(sender=acct, app_id=self.identity_app)
        with self.ctx.txn.create_group(gtxns=[pay, call], active_txn_index=1):
            return self.identity.new_agent(pay, arc4.String(domain)).native

    def deregister(self, acct, agent_id):
        with self.ctx.txn.create_group(active_txn_overrides={"sender": acct}):
            return self.identity.deregister_agent(arc4.UInt64(agent_id))

    def call(self, sender, fn, *args):
        with self.ctx.txn.create_group(active_txn_overrides={"sender": sender}):
            return fn(*args)

    def post_job(self, client, budget, validator_id=0):
        pay = self._pay(client, self.validation_app.address, MBR)
        return self._grouped(
            client, [pay],
            lambda: self.validation.post_job(pay, H, arc4.UInt64(budget), arc4.UInt64(validator_id)),
        ).native

    def fund(self, client, job_id, amount):
        mbr = self._pay(client, self.validation_app.address, MBR)
        axfer = self.ctx.any.txn.asset_transfer(
            sender=client,
            asset_receiver=self.validation_app.address,
            xfer_asset=self.usdc,
            asset_amount=UInt64(amount),
        )
        return self._grouped(
            client, [mbr, axfer],
            lambda: self.validation.fund_job(mbr, axfer, arc4.UInt64(job_id)),
        ).native

    def bid(self, bidder, job_id, agent_id, price):
        pay = self._pay(bidder, self.validation_app.address, MBR)
        return self._grouped(
            bidder, [pay],
            lambda: self.validation.place_bid(
                pay, arc4.UInt64(job_id), arc4.UInt64(agent_id), arc4.UInt64(price), H
            ),
        )

    def submit(self, worker, job_id):
        pay = self._pay(worker, self.validation_app.address, MBR)
        return self._grouped(
            worker, [pay],
            lambda: self.validation.submit_result(pay, arc4.UInt64(job_id), H),
        )

    def itxns(self):
        """(receiver, amount) for every inner asset transfer of the last group."""
        out = []
        for grp in self.ctx.txn.last_group.itxn_groups:
            for it in grp:
                try:
                    out.append((it.asset_receiver, int(it.asset_amount)))
                except Exception:  # noqa: BLE001 -- payments have no asset_receiver
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


def _worker_job(world, validator_id=0, budget=1_000_000, escrow=None):
    ctx = world.ctx
    client = ctx.any.account()
    worker_acct = ctx.any.account()
    worker = world.register(worker_acct, "worker.example")
    jid = world.post_job(client, budget, validator_id)
    world.call(client, world.validation.assign_job, arc4.UInt64(jid), arc4.UInt64(worker))
    if escrow:
        world.fund(client, jid, escrow)
    return client, worker_acct, worker, jid


# --- R-4: escrow capped at budget, excess refunded to the client ----------


def test_R4_release_caps_at_budget_and_refunds_excess_to_client(world):
    """Fund at 1.0, accept a 0.4 bid (budget drops to 0.4), then anyone releases
    after the window: the worker gets 0.4, the client gets the 0.6 back — not the
    worker. Before the fix the whole 1.0 went to the worker with no client exit."""
    ctx = world.ctx
    client = ctx.any.account()
    worker_acct = ctx.any.account()
    worker = world.register(worker_acct, "w.example")

    jid = world.post_job(client, 1_000_000)
    world.fund(client, jid, 1_000_000)
    world.bid(worker_acct, jid, worker, 400_000)
    world.call(client, world.validation.accept_bid, arc4.UInt64(jid), arc4.UInt64(worker))

    world.submit(worker_acct, jid)
    world.call(client, world.validation.validation_response, arc4.UInt64(jid), arc4.Bool(True))

    world.advance(301)
    stranger = ctx.any.account()
    paid = world.call(stranger, world.validation.release_escrow, arc4.UInt64(jid)).native
    xfers = world.itxns()
    assert paid == 400_000
    assert (worker_acct, 400_000) in xfers, "worker paid the agreed 0.4"
    assert (client, 600_000) in xfers, "client recovered the 0.6 excess"


def test_R4_fund_job_refuses_to_exceed_the_budget(world):
    client, worker_acct, worker, jid = _worker_job(world, budget=500_000)
    with pytest.raises(Exception, match="cannot exceed the agreed budget"):
        world.fund(client, jid, 500_001)


# --- R-F1: client fallback judge + two-window expire -----------------------


def test_RF1_client_cannot_judge_before_the_validator_window_but_can_after(world):
    ctx = world.ctx
    validator_acct = ctx.any.account()
    validator = world.register(validator_acct, "v.example")
    client, worker_acct, worker, jid = _worker_job(world, validator_id=validator, escrow=1_000_000)
    world.submit(worker_acct, jid)

    # inside the validator's window the client is refused
    with pytest.raises(Exception, match="only the named validator may judge"):
        world.call(client, world.validation.validation_response, arc4.UInt64(jid), arc4.Bool(False))

    # after the window the client may judge — here, dispute the garbage result
    world.advance(301)
    world.call(client, world.validation.validation_response, arc4.UInt64(jid), arc4.Bool(False))
    assert world.call(client, world.validation.get_job, arc4.UInt64(jid)).status.native == 4  # DISPUTED
    # and can now get their money back, fee-free
    back = world.call(client, world.validation.refund_escrow, arc4.UInt64(jid)).native
    assert back == 1_000_000


def test_RF1b_dead_validator_no_longer_strands_the_job(world):
    """A validator that deregisters after assignment left NOBODY able to judge.
    The client fallback (which does not resolve the validator id) now rescues
    it."""
    ctx = world.ctx
    validator_acct = ctx.any.account()
    validator = world.register(validator_acct, "v.example")
    client, worker_acct, worker, jid = _worker_job(world, validator_id=validator, escrow=1_000_000)
    world.submit(worker_acct, jid)
    world.deregister(validator_acct, validator)

    world.advance(301)
    world.call(client, world.validation.validation_response, arc4.UInt64(jid), arc4.Bool(True))
    assert world.call(client, world.validation.get_job, arc4.UInt64(jid)).status.native == 3  # VALIDATED


def test_RF1_expire_verdict_waits_two_windows(world):
    ctx = world.ctx
    validator = world.register(ctx.any.account(), "v.example")
    client, worker_acct, worker, jid = _worker_job(world, validator_id=validator, escrow=1_000_000)
    world.submit(worker_acct, jid)

    world.advance(301)  # one window
    with pytest.raises(Exception, match="still have time"):
        world.call(ctx.any.account(), world.validation.expire_verdict, arc4.UInt64(jid))

    world.advance(301)  # second window
    world.call(ctx.any.account(), world.validation.expire_verdict, arc4.UInt64(jid))
    assert world.call(client, world.validation.get_job, arc4.UInt64(jid)).status.native == 3


# --- R-8: reclaim a stranded validated escrow ------------------------------


def test_R8_client_reclaims_escrow_stranded_by_a_departed_worker(world):
    ctx = world.ctx
    client, worker_acct, worker, jid = _worker_job(world, escrow=1_000_000)
    world.submit(worker_acct, jid)
    world.call(client, world.validation.validation_response, arc4.UInt64(jid), arc4.Bool(True))

    # the worker deregisters, so release can never resolve a payee
    world.deregister(worker_acct, worker)
    with pytest.raises(Exception, match="unknown agent"):
        world.call(client, world.validation.release_escrow, arc4.UInt64(jid))

    # too early to reclaim
    world.advance(301)
    with pytest.raises(Exception, match="still has time to be paid"):
        world.call(client, world.validation.reclaim_stranded, arc4.UInt64(jid))

    # after four windows the client recovers it, fee-free
    world.advance(4 * 300)
    back = world.call(client, world.validation.reclaim_stranded, arc4.UInt64(jid)).native
    assert back == 1_000_000
    assert (client, 1_000_000) in world.itxns()


# --- R-2: refunds take no protocol fee -------------------------------------


def test_R2_refund_of_a_cancelled_job_takes_no_fee(world):
    ctx = world.ctx
    treasury = ctx.any.account(opted_asset_balances={world.usdc.id: UInt64(0)})
    world.call(world.creator, world.validation.set_fee, arc4.UInt64(250), arc4.Address(treasury))

    client = ctx.any.account()
    jid = world.post_job(client, 1_000_000)
    world.fund(client, jid, 1_000_000)
    world.call(client, world.validation.cancel_job, arc4.UInt64(jid))

    back = world.call(ctx.any.account(), world.validation.refund_escrow, arc4.UInt64(jid)).native
    xfers = world.itxns()
    assert back == 1_000_000, "the client gets everything back"
    assert (treasury, 25_000) not in xfers, "no fee is taken on a refund"


def test_R2_settlement_still_takes_the_fee(world):
    """The fee still applies to a real payout, so the charge_fee flag didn't
    disable it everywhere."""
    ctx = world.ctx
    treasury = ctx.any.account(opted_asset_balances={world.usdc.id: UInt64(0)})
    world.call(world.creator, world.validation.set_fee, arc4.UInt64(250), arc4.Address(treasury))
    client, worker_acct, worker, jid = _worker_job(world, escrow=1_000_000)
    world.submit(worker_acct, jid)
    world.call(client, world.validation.validation_response, arc4.UInt64(jid), arc4.Bool(True))
    paid = world.call(client, world.validation.release_escrow, arc4.UInt64(jid)).native
    assert paid == 975_000
    assert (treasury, 25_000) in world.itxns()


# --- R-3: the verdict records without the reputation app -------------------


def test_R3_validation_response_does_not_touch_reputation(world):
    """Judging a job must not depend on the reputation app's storage. If
    validation_response still inner-called it, the abi_call shim would fire and
    record a score; it must not. The verdict lives only on the job until
    record_job_verdict syncs it as a separate, funded step."""
    ctx = world.ctx
    client, worker_acct, worker, jid = _worker_job(world, escrow=1_000_000)
    world.submit(worker_acct, jid)
    world.call(client, world.validation.validation_response, arc4.UInt64(jid), arc4.Bool(True))

    # reputation was never written by the verdict: if validation_response still
    # inner-called it, the shim would have created a score with validated == 1.
    score = world.call(client, world.reputation.get_score, arc4.UInt64(worker))
    assert score.validated.native == 0, "no verdict was written to the score by validation_response"

    # the separate, funded sync writes it, and is idempotent
    mbr = world._pay(client, world.reputation_app.address, 37_000)
    world._grouped(client, [mbr], lambda: world.validation.record_job_verdict(mbr, arc4.UInt64(jid)))
    score = world.call(client, world.reputation.get_score, arc4.UInt64(worker))
    assert score.validated.native == 1
    mbr2 = world._pay(client, world.reputation_app.address, 37_000)
    with pytest.raises(Exception, match="already recorded"):
        world._grouped(client, [mbr2], lambda: world.validation.record_job_verdict(mbr2, arc4.UInt64(jid)))
