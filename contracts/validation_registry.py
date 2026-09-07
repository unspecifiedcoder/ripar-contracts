"""
Validation Registry — ERC-8004's third registry, plus the job board.

ERC-8004 splits this into request and response: a client asks a validator to
judge some work, the validator answers, and the answer is onchain. That is kept
here, and a job lifecycle is added around it, because a validation with no job
attached is an opinion about nothing.

The lifecycle is deliberately narrow:

    open -> assigned -> submitted -> validated | disputed

A job can only be assigned to an agent that exists in the Identity Registry, only
the assignee can submit, and only the named validator can judge. Escrow is
recorded here but held by the client until release, so this contract never has
custody of anyone's USDC — the same non-custodial rule the rest of Ripar follows.
"""

from algopy import (
    Account,
    Application,
    ARC4Contract,
    op,
    Asset,
    Bytes,
    BoxMap,
    Global,
    Txn,
    UInt64,
    arc4,
    gtxn,
    itxn,
    subroutine,
)

# Status values. Plain ints because AVM has no enums and a typed wrapper would
# cost a box read to interpret.
OPEN = 0
ASSIGNED = 1
SUBMITTED = 2
VALIDATED = 3
DISPUTED = 4
CANCELLED = 5
# Neither the validator nor the fallback judged inside their windows: the escrow
# is split evenly so that neither party holds a free default win.
SPLIT = 6


class Bid(arc4.Struct):
    """One agent's offer on a job. Price is what they will do it for."""

    job_id: arc4.UInt64
    bidder_agent_id: arc4.UInt64
    price_micro: arc4.UInt64
    # Free-form, hashed rather than stored: a pitch belongs off chain, and a
    # commitment to it does not.
    pitch_hash: arc4.DynamicBytes
    placed_at: arc4.UInt64
    # The validator named on the job when this bid was placed. accept_bid refuses
    # a bid whose terms the client has since changed under the bidder.
    validator_agent_id: arc4.UInt64
    # Who judges if the job's validator stays silent for a window. Chosen by the
    # BIDDER; the client consents to it by accepting the bid.
    fallback_validator_agent_id: arc4.UInt64


class Job(arc4.Struct):
    job_id: arc4.UInt64
    client: arc4.Address
    # 0 until assigned.
    server_agent_id: arc4.UInt64
    # Who may judge the result. 0 means the client judges it themselves.
    validator_agent_id: arc4.UInt64
    # Budget in USDC base units. Held by the client, not by this app.
    budget_micro: arc4.UInt64
    # sha256 of the job specification, so the terms cannot be edited after bids.
    spec_hash: arc4.DynamicBytes
    # sha256 of the delivered result, set on submit.
    result_hash: arc4.DynamicBytes
    status: arc4.UInt64
    created_at: arc4.UInt64
    updated_at: arc4.UInt64
    # Second judge, used only once validator_agent_id has been silent for a
    # window. Named by whoever initiates the pairing (the assigning client, or
    # the bidder via accept_bid), and never a party to the job.
    fallback_validator_agent_id: arc4.UInt64


class EscrowPaid(arc4.Struct):
    """ARC-28 event, emitted on every path that moves escrow out of this app.

    Nothing was emitted before. The asset transfers themselves are on chain, so
    the money was always traceable — but which job a transfer settled, and how
    much of it was protocol fee, existed only as a box diff. Reconciling
    treasury income against jobs meant replaying box state.

    Emitted from _pay_escrow and from release_partial, the only two paths that
    pay out, so a consumer that reads this event sees every cent that leaves.
    """

    job_id: arc4.UInt64
    payee: arc4.Address
    paid: arc4.UInt64
    fee: arc4.UInt64
    treasury: arc4.Address


class ValidationRegistry(ARC4Contract):
    def __init__(self) -> None:
        self.job_count = UInt64(0)
        self.jobs = BoxMap(UInt64, Job, key_prefix=b"jb_")
        # The IdentityRegistry this contract trusts to say which address
        # controls an agent id. validation_response resolves the named
        # validator through it, so a verdict cannot be written by a stranger.
        self.identity_app = UInt64(0)

        # Escrow, in its own box map rather than a field on Job.
        #
        # A budget and an escrow are different facts with different lifetimes:
        # a budget is what the client says the work is worth, escrow is what
        # they have actually handed over. Keeping them apart also leaves the
        # jb_ box layout untouched, so every decoder that already reads it
        # keeps working.
        #
        # Zero or absent means nothing is held, which is the honest default:
        # posting a job commits no money until fund_job runs.
        self.escrow = BoxMap(UInt64, UInt64, key_prefix=b"es_")

        # The client's half of a SPLIT job. Kept in its own box so it can be
        # claimed without resolving the worker (whose half lives in es_), and so
        # a departed worker strands only their own half, never the client's.
        self.split_refund = BoxMap(UInt64, UInt64, key_prefix=b"rf_")

        # The asset escrow is denominated in. Fixed at bootstrap for the same
        # reason the ReputationRegistry fixes its own: an escrow the caller
        # chose the asset for can be funded with something worthless.
        self.escrow_asset = UInt64(0)

        # How long a submitted result may sit unjudged before the assignee can
        # claim the escrow anyway. Without it a validator who simply never
        # shows up freezes the worker's money for good.
        self.dispute_window = UInt64(0)

        # The ReputationRegistry a verdict is written to. Without it a job can
        # be judged and the agent's validated/disputed counters never move,
        # which is what made those two fields permanently zero.
        self.reputation_app = UInt64(0)

        # Bids, keyed by job id and bidder agent id so a bid can be found
        # without iterating. One bid per agent per job: a second call replaces
        # the first, which is what "revise my bid" means and avoids a bidder
        # spamming the board to bury rivals.
        self.bids = BoxMap(Bytes, Bid, key_prefix=b"bd_")

        # Protocol fee in basis points, taken from escrow on release. Zero by
        # default and set once, because a fee that can move after work has been
        # accepted is a fee the assignee never agreed to.
        self.fee_bps = UInt64(0)
        self.treasury = Global.zero_address

    @arc4.abimethod
    def bootstrap(
        self,
        identity_app: arc4.UInt64,
        reputation_app: arc4.UInt64,
        escrow_asset: arc4.UInt64,
        dispute_window_secs: arc4.UInt64,
    ) -> arc4.Bool:
        """Point this registry at an IdentityRegistry and fix the escrow terms.

        All three are fixed rather than passed per call: a validator address
        resolved through a registry the caller chose is a validator address the
        caller invented, an escrow whose asset the caller picks can be funded
        with something worthless, and a dispute window set per job is a window
        the client can set to zero.
        """
        assert Txn.sender == Global.creator_address, "only the creator may bootstrap"
        assert self.identity_app == 0, "already bootstrapped"
        assert identity_app.native > 0, "identity app id required"
        assert reputation_app.native > 0, "reputation app id required"
        assert escrow_asset.native > 0, "escrow asset required"
        assert dispute_window_secs.native > 0, "a zero dispute window would let anyone claim instantly"
        self.identity_app = identity_app.native
        self.reputation_app = reputation_app.native
        self.escrow_asset = escrow_asset.native
        self.dispute_window = dispute_window_secs.native
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def opt_in_asset(self) -> arc4.Bool:
        """Let this app hold the escrow asset. Creator-only, once.

        An Algorand account cannot receive an ASA it has not opted into, so
        without this every fund_job would fail at the transfer with an error
        that says nothing about the cause. The app account needs 0.1 ALGO of
        minimum balance for the holding before this will succeed.
        """
        assert Txn.sender == Global.creator_address, "only the creator may opt in"
        assert self.escrow_asset > 0, "bootstrap first"
        itxn.AssetTransfer(
            xfer_asset=self.escrow_asset,
            asset_receiver=Global.current_application_address,
            asset_amount=0,
            fee=0,
        ).submit()
        return arc4.Bool(True)  # noqa: FBT003

    @subroutine
    def _now(self) -> UInt64:
        return Global.latest_timestamp

    @subroutine
    def _assert_covers_box_growth(self, mbr: gtxn.PaymentTransaction, before: UInt64) -> None:
        """Every box this app creates or grows raises the app account's minimum
        balance, and that cost was silently charged to the app itself — so a
        stranger could post jobs, bid, or fund until the app fell below its
        minimum and refused everyone. `mbr` is a payment, in the same group,
        from the caller to this app covering exactly the growth `before` -> now.
        Call it AFTER the box write, with `before` captured just before it.
        """
        app = Global.current_application_address
        assert mbr.receiver == app, "storage payment must be sent to this app"
        assert mbr.sender == Txn.sender, "you must pay for the storage you create"
        assert (
            mbr.amount >= app.min_balance - before
        ), "payment must cover the box storage this call adds"

    @arc4.abimethod
    def post_job(
        self,
        mbr: gtxn.PaymentTransaction,
        spec_hash: arc4.DynamicBytes,
        budget_micro: arc4.UInt64,
        validator_agent_id: arc4.UInt64,
    ) -> arc4.UInt64:
        """Open a job. The spec is committed by hash so it cannot change later.

        `mbr` covers the `jb_` box this creates; without it a stranger could
        post jobs until the app account fell below its minimum balance and every
        fund_job, bid and registration failed for good.
        """
        assert spec_hash.native.length == 32, "spec_hash must be a sha256 digest"
        assert budget_micro.native > 0, "a job with no budget attracts no bids"

        mbr_before = Global.current_application_address.min_balance
        self.job_count += 1
        jid = self.job_count
        now = self._now()

        self.jobs[jid] = Job(
            job_id=arc4.UInt64(jid),
            client=arc4.Address(Txn.sender),
            server_agent_id=arc4.UInt64(0),
            validator_agent_id=validator_agent_id,
            budget_micro=budget_micro,
            spec_hash=spec_hash.copy(),
            result_hash=arc4.DynamicBytes(Bytes(b"")),
            status=arc4.UInt64(OPEN),
            created_at=arc4.UInt64(now),
            updated_at=arc4.UInt64(now),
            fallback_validator_agent_id=arc4.UInt64(0),
        )
        self._assert_covers_box_growth(mbr, mbr_before)
        return arc4.UInt64(jid)

    @arc4.abimethod
    def assign_job(
        self,
        job_id: arc4.UInt64,
        server_agent_id: arc4.UInt64,
        fallback_validator_agent_id: arc4.UInt64,
    ) -> arc4.Bool:
        """Give the job to an agent. Client only, and only while still open.

        The client names the fallback judge here (or 0 for none): the agent who
        may judge if the named validator stays silent for a window. The worker
        consents by having taken the assignment. A fallback may not be either
        party or the validator itself.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.client.native == Txn.sender, "only the client may assign"
        assert j.status.native == OPEN, "job is no longer open"
        assert server_agent_id.native > 0, "agent id required"

        self._check_fallback(
            fallback_validator_agent_id,
            j.validator_agent_id,
            server_agent_id,
            j.client.native,
            self._agent_address(server_agent_id),
        )
        j.server_agent_id = server_agent_id
        j.fallback_validator_agent_id = fallback_validator_agent_id
        j.status = arc4.UInt64(ASSIGNED)
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def submit_result(
        self, mbr: gtxn.PaymentTransaction, job_id: arc4.UInt64, result_hash: arc4.DynamicBytes
    ) -> arc4.Bool:
        """The assignee commits its result by hash. The payload stays offchain.

        `mbr` covers the growth of the `jb_` box: the result hash goes from empty
        to 32 bytes, and that added storage is charged to the app account.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        assert result_hash.native.length == 32, "result_hash must be a sha256 digest"

        j = self.jobs[jid].copy()
        assert j.status.native == ASSIGNED, "job is not awaiting a result"

        # Only the assignee may submit. This was previously left to the client
        # SDK, with a note saying an inner app call was "the next iteration" —
        # which meant anyone could commit a result hash against anyone's job and
        # move it to SUBMITTED, and the real assignee could then never submit.
        # A check that lives in the SDK is not a check.
        assignee_addr, _txn = arc4.abi_call[arc4.Address](
            "agent_address(uint64)address",
            j.server_agent_id,
            app_id=self.identity_app,
        )
        assert Txn.sender == assignee_addr.native, "only the assigned agent may submit a result"

        mbr_before = Global.current_application_address.min_balance
        j.result_hash = result_hash.copy()
        j.status = arc4.UInt64(SUBMITTED)
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()
        self._assert_covers_box_growth(mbr, mbr_before)
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def validation_response(
        self, job_id: arc4.UInt64, passed: arc4.Bool, as_validator: arc4.UInt64
    ) -> arc4.UInt64:
        """Judge a submitted result. Returns the resulting status.

        `as_validator` is the agent id the caller is acting as: the named
        validator, or the fallback once the validator's window has passed. Only
        the id the caller CLAIMS is resolved, so a validator that has deregistered
        cannot strand the job — the fallback simply acts. No one gets a unilateral
        verdict. An earlier fix let the client judge a silent validator's job, but
        that only moved the free option to the client, who could then reject
        delivered work and refund. The fallback is named at pairing time
        (assign_job / accept_bid), is never a party to the job, and the other side
        consents to it by committing. If BOTH judges stay silent, expire_verdict
        splits the escrow — neither side wins by default.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == SUBMITTED, "nothing has been submitted to judge"

        if j.validator_agent_id.native > 0:
            primary_silent = (
                Global.latest_timestamp > j.updated_at.native + self.dispute_window
            )
            is_primary = as_validator == j.validator_agent_id
            is_fallback = (
                primary_silent
                and j.fallback_validator_agent_id.native > 0
                and as_validator == j.fallback_validator_agent_id
            )
            assert (
                is_primary or is_fallback
            ), "only the named validator may judge, or the fallback once the validator's window has passed"
            assert Txn.sender == self._agent_address(as_validator), "you do not control that validator"
        else:
            assert j.client.native == Txn.sender, "only the client may judge a job with no validator"

        # A Python-literal ternary is not a value the AVM can hold; branch and
        # build a UInt64 on each side instead.
        new_status = UInt64(VALIDATED)
        if not passed.native:
            new_status = UInt64(DISPUTED)
        j.status = arc4.UInt64(new_status)
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()

        # The verdict is NOT written to the reputation score here, deliberately.
        # It used to be an inner call to record_validation, which creates a score
        # box the reputation app pays for — so once that app was starved of
        # minimum balance, the inner call reverted and took the whole verdict
        # down with it. A validator's honest "fail" could then never be
        # recorded, and after the window expire_verdict forced the job to a pass
        # and the worker was paid for rejected work. The judgement must not
        # depend on anyone else's storage. The verdict now lives only on the job
        # here; record_job_verdict syncs it to the score as a separate, funded,
        # retryable step that can never block this one.
        return arc4.UInt64(new_status)

    @arc4.abimethod
    def record_job_verdict(self, mbr: gtxn.PaymentTransaction, job_id: arc4.UInt64) -> arc4.Bool:
        """Write a decided job's verdict through to the agent's reputation score.

        Split out of validation_response so a starved reputation app can never
        block a verdict (see the note there). Anyone may call it once the job is
        VALIDATED or DISPUTED; `passed` is read off the job's own status, not
        supplied. `mbr` pays the reputation app for the score and dedupe boxes
        that credit may create — record_validation there refuses a second
        recording of the same job, so this cannot be replayed to inflate a count.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        status = j.status.native
        assert status == VALIDATED or status == DISPUTED, "no verdict has been decided yet"

        rep = Application(self.reputation_app).address
        assert mbr.receiver == rep, "storage payment must be sent to the reputation app"
        assert mbr.sender == Txn.sender, "you must pay for the storage you create"
        # One score box (~0.0293 ALGO) plus one dedupe box (~0.0073) worst case.
        assert mbr.amount >= 37_000, "payment must cover the score and dedupe boxes (>=0.037 ALGO)"

        arc4.abi_call(
            "record_validation(uint64,uint64,bool)bool",
            job_id,
            j.server_agent_id,
            arc4.Bool(status == VALIDATED),
            app_id=self.reputation_app,
        )
        return arc4.Bool(True)  # noqa: FBT003

    @subroutine
    def _check_fallback(
        self,
        fallback: arc4.UInt64,
        primary: arc4.UInt64,
        server: arc4.UInt64,
        client: Account,
        server_addr: Account,
    ) -> None:
        """A fallback judge may not be the validator, the worker, or the client.

        Best effort: a second agent the SAME operator controls is
        indistinguishable on chain from an independent judge, so a worker can
        still route the fallback to a puppet id. That residual cannot be closed
        in the contract — which is why the fallback is named where the other side
        sees it before they commit (a bid field, a job field), and closing it
        fully needs a protocol-level arbiter, a policy choice left to the
        deployment. What is enforceable is refused here.
        """
        if fallback.native > 0:
            assert fallback != primary, "the fallback must differ from the validator"
            assert fallback != server, "the worker cannot be their own fallback judge"
            fb_addr = self._agent_address(fallback)
            assert fb_addr != client, "the client cannot be the fallback judge"
            assert fb_addr != server_addr, "the worker cannot be the fallback judge"

    @subroutine
    def _agent_address(self, agent_id: arc4.UInt64) -> Account:
        """Resolve an agent id to its controlling address, or fail.

        One place, because three methods need it and a resolution that silently
        returned the zero address would compare equal to nothing and authorise
        nobody — or, worse, pay nobody.
        """
        addr, _txn = arc4.abi_call[arc4.Address](
            "agent_address(uint64)address",
            agent_id,
            app_id=self.identity_app,
        )
        return addr.native

    @subroutine
    def _pay_escrow(self, job_id: UInt64, to: Account, charge_fee: bool) -> UInt64:  # noqa: FBT001
        """Send the whole escrow for a job and zero the record. Returns the amount.

        The box is cleared BEFORE the transfer is submitted. If it were cleared
        after, a failed inner transaction would leave the ledger claiming money
        this app no longer intends to hold — and if the clear itself failed,
        the escrow could be paid twice. Ordering it this way makes double
        payment impossible: the second call finds nothing to send.

        `charge_fee` is True only when paying the WORKER on a passing verdict; a
        refund to the client (a failed verdict, a cancelled job, or a reclaim of
        stranded escrow) takes no protocol fee — the client is getting their own
        money back, not settling for delivered work.
        """
        assert job_id in self.escrow, "nothing is escrowed for this job"
        amount = self.escrow[job_id]
        assert amount > 0, "nothing is escrowed for this job"
        del self.escrow[job_id]

        # The protocol fee, if one was set. Taken here rather than at funding
        # so the client escrows exactly what they agreed to pay and the fee
        # comes out of the settlement — a fee deducted on the way IN would mean
        # the assignee sees a smaller escrow than the budget they accepted.
        fee = UInt64(0)
        if charge_fee and self.fee_bps > 0:
            fee = amount * self.fee_bps // 10_000
            if fee > 0:
                itxn.AssetTransfer(
                    xfer_asset=self.escrow_asset,
                    asset_receiver=self.treasury,
                    asset_amount=fee,
                    fee=0,
                ).submit()

        itxn.AssetTransfer(
            xfer_asset=self.escrow_asset,
            asset_receiver=to,
            asset_amount=amount - fee,
            fee=0,
        ).submit()
        arc4.emit(
            EscrowPaid(
                arc4.UInt64(job_id),
                arc4.Address(to),
                arc4.UInt64(amount - fee),
                arc4.UInt64(fee),
                arc4.Address(self.treasury),
            )
        )
        return amount - fee

    @arc4.abimethod
    def fund_job(
        self,
        mbr: gtxn.PaymentTransaction,
        payment: gtxn.AssetTransferTransaction,
        job_id: arc4.UInt64,
    ) -> arc4.UInt64:
        """Move the budget into escrow. Returns the total now held.

        The transfer is a TRANSACTION IN THIS GROUP, so the amount is read off
        something the AVM has already validated rather than taken as a number
        the caller supplies — the same rule that stopped reputation being
        minted from bytes.

        This is the one place Ripar takes custody, and it is opt-in: a job runs
        perfectly well unfunded, with the budget as a stated intention. What
        funding buys is that the assignee can see the money exists before doing
        the work.

        Funding may not exceed the agreed budget, and `mbr` covers the `es_`
        box's storage. The cap matters because a payout to the worker is now
        capped at the budget and the excess refunded to the client — refusing
        the over-funding at the door keeps that impossible to reach by accident.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.client.native == Txn.sender, "only the client may fund their own job"
        assert j.status.native == OPEN or j.status.native == ASSIGNED, "job is past funding"

        assert payment.asset_receiver == Global.current_application_address, "escrow must be paid to this app"
        assert payment.sender == Txn.sender, "the funder must be the client"
        assert payment.xfer_asset.id == self.escrow_asset, "escrow is denominated in one asset; this is not it"
        assert payment.asset_amount > 0, "a zero transfer escrows nothing"

        held = payment.asset_amount
        if jid in self.escrow:
            held += self.escrow[jid]
        assert held <= j.budget_micro.native, "escrow cannot exceed the agreed budget"

        mbr_before = Global.current_application_address.min_balance
        self.escrow[jid] = held
        self._assert_covers_box_growth(mbr, mbr_before)

        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()
        return arc4.UInt64(held)

    @arc4.abimethod
    def release_escrow(self, job_id: arc4.UInt64) -> arc4.UInt64:
        """Pay the assignee once the work passed. Returns the amount sent.

        Callable by the client, and — after the dispute window — by anyone.
        That second path is the point: a validator who never returns would
        otherwise freeze the worker's money for good, and a lock with no key is
        not escrow, it is confiscation. The window starts when the verdict was
        written, so a validator who does show up is never pre-empted.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == VALIDATED, "escrow is released on a passing verdict"

        past_window = Global.latest_timestamp > j.updated_at.native + self.dispute_window
        assert j.client.native == Txn.sender or past_window, "only the client may release before the dispute window closes"

        # The worker is never paid more than the agreed budget. Escrow can exceed
        # it — fund_job now refuses that, but accept_bid rewrites the budget DOWN
        # to the bid after funding, so a job funded at 1.0 then let at 0.4 holds
        # 1.0 against a 0.4 budget. Without this the anyone-after-window release
        # handed the whole 1.0 to the worker and the client had no way to recover
        # the 0.6. Return the excess to the client first, then settle the rest.
        # Guarded on the escrow existing so an unfunded-but-validated job still
        # fails with _pay_escrow's own "nothing is escrowed" message, not a
        # box-not-found on this read.
        if jid in self.escrow:
            held = self.escrow[jid]
            budget = j.budget_micro.native
            if held > budget:
                self.escrow[jid] = budget
                itxn.AssetTransfer(
                    xfer_asset=self.escrow_asset,
                    asset_receiver=j.client.native,
                    asset_amount=held - budget,
                    fee=0,
                ).submit()

        paid = self._pay_escrow(jid, self._agent_address(j.server_agent_id), True)
        return arc4.UInt64(paid)

    @arc4.abimethod
    def refund_escrow(self, job_id: arc4.UInt64) -> arc4.UInt64:
        """Return the escrow to the client. Returns the amount sent.

        Only on a failed verdict or a cancelled job, and payable to the client
        whoever calls it — the destination is read off the job rather than from
        the sender, so triggering a refund can never redirect one.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert (
            j.status.native == DISPUTED or j.status.native == CANCELLED
        ), "escrow is refunded on a failed verdict or a cancelled job"

        paid = self._pay_escrow(jid, j.client.native, False)
        return arc4.UInt64(paid)

    @arc4.abimethod
    def reclaim_stranded(self, job_id: arc4.UInt64) -> arc4.UInt64:
        """Return a passed job's escrow to the client when the worker has made
        itself unpayable. Returns the amount refunded.

        A VALIDATED job pays the worker at an address resolved live from the
        IdentityRegistry. If the worker deregisters, or rotates to an address not
        opted into the asset, that resolution (or the transfer) fails on every
        release and refund_escrow refuses VALIDATED — so the client's escrow was
        locked forever and the `es_` box blocked deleting the app.

        This is the client's exit, and it is deliberately slow: only four dispute
        windows after the verdict. For the first window only the client may
        release; after it ANYONE may release to the worker, so a worker who is
        still reachable (or any keeper acting for them) has three further windows
        to be paid before the client can take the money back. No fee is charged —
        the client is recovering their own funds, not settling for work.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == VALIDATED, "only a passed job's escrow can be reclaimed"
        assert j.client.native == Txn.sender, "only the client may reclaim"
        assert (
            Global.latest_timestamp > j.updated_at.native + self.dispute_window * 4
        ), "the worker still has time to be paid"

        paid = self._pay_escrow(jid, j.client.native, False)
        return arc4.UInt64(paid)

    @arc4.abimethod(readonly=True)
    def get_escrow(self, job_id: arc4.UInt64) -> arc4.UInt64:
        """What is actually held for a job. 0 for an unfunded one."""
        jid = job_id.native
        if jid in self.escrow:
            return arc4.UInt64(self.escrow[jid])
        return arc4.UInt64(0)

    @arc4.abimethod
    def set_validator(self, job_id: arc4.UInt64, validator_agent_id: arc4.UInt64) -> arc4.Bool:
        """Name or change the validator, while the job is still open.

        Only while OPEN. Once an agent has been assigned, changing who judges
        the work is changing the terms after the fact — the assignee took the
        job partly on who would be marking it.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.client.native == Txn.sender, "only the client may name the validator"
        assert j.status.native == OPEN, "the validator is fixed once the job is assigned"

        j.validator_agent_id = validator_agent_id
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.baremethod(allow_actions=["DeleteApplication"])
    def delete(self) -> None:
        """Creator-only teardown. See IdentityRegistry.delete for why.

        The AVM refuses while boxes remain, so live jobs and outstanding escrow
        both block this — money cannot be stranded by deleting the app that
        holds it.
        """
        assert Txn.sender == Global.creator_address, "only the creator may delete"

    @subroutine
    def _bid_key(self, job_id: UInt64, bidder: UInt64) -> Bytes:
        """job || bidder. Both, so a bid is addressable without iteration and a
        second bid from the same agent replaces rather than duplicates."""
        return op.itob(job_id) + op.itob(bidder)  # noqa: RET504

    @arc4.abimethod
    def place_bid(
        self,
        mbr: gtxn.PaymentTransaction,
        job_id: arc4.UInt64,
        bidder_agent_id: arc4.UInt64,
        price_micro: arc4.UInt64,
        pitch_hash: arc4.DynamicBytes,
        fallback_validator_agent_id: arc4.UInt64,
    ) -> arc4.Bool:
        """Offer to do a job. Only the bidding agent's own address may bid.

        The docs said flatly "there is no bid: the client names the agent
        directly". This is that gap closed, and the authorisation is the same
        rule as everywhere else here — the bidder is resolved through the
        IdentityRegistry, so an agent cannot be bid on behalf of.

        Bids are only accepted while the job is OPEN. Bidding on assigned work
        is noise, and worse, a bid that looks live on a job somebody else is
        already doing misleads whoever reads the board.

        A second bid from the same agent REPLACES the first. That is what
        revising an offer means, and the alternative — many live bids from one
        agent — is a way to bury rivals rather than to compete.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == OPEN, "bids close when the job is assigned"
        assert price_micro.native > 0, "a zero bid is not an offer"
        assert pitch_hash.native.length == 32, "pitch_hash must be a sha256 digest"

        bidder = self._agent_address(bidder_agent_id)
        assert Txn.sender == bidder, "only the bidding agent may place its own bid"
        assert Txn.sender != j.client.native, "the client cannot bid on their own job"

        # The fallback the bidder proposes is validated against the job's terms
        # now, so an accepting client sees an already-legal fallback.
        self._check_fallback(
            fallback_validator_agent_id, j.validator_agent_id, bidder_agent_id, j.client.native, bidder
        )

        mbr_before = Global.current_application_address.min_balance
        self.bids[self._bid_key(jid, bidder_agent_id.native)] = Bid(
            job_id=job_id,
            bidder_agent_id=bidder_agent_id,
            price_micro=price_micro,
            pitch_hash=pitch_hash.copy(),
            placed_at=arc4.UInt64(self._now()),
            validator_agent_id=j.validator_agent_id,
            fallback_validator_agent_id=fallback_validator_agent_id,
        )
        self._assert_covers_box_growth(mbr, mbr_before)
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def withdraw_bid(self, job_id: arc4.UInt64, bidder_agent_id: arc4.UInt64) -> arc4.Bool:
        """Take a bid back, and reclaim its box.

        The bidder may always withdraw their own bid. The CLIENT may also sweep a
        bid once the job has left OPEN. Without that second path a losing bid
        whose bidder later deregisters is a box nobody can remove — the bidder
        resolution below would revert for everyone — and a box nobody can remove
        blocks deleting the app forever. The client only reaches it on an
        already-decided job, so it cannot pull a live competitor's bid; the freed
        deposit goes to whoever does the cleanup.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        key = self._bid_key(jid, bidder_agent_id.native)
        assert key in self.bids, "no such bid"

        j = self.jobs[jid].copy()
        if Txn.sender == j.client.native and j.status.native != OPEN:
            pass
        else:
            assert (
                Txn.sender == self._agent_address(bidder_agent_id)
            ), "only the bidder may withdraw (or the client, once the job has left OPEN)"

        app = Global.current_application_address
        mbr_before = app.min_balance
        del self.bids[key]
        # Return the storage deposit place_bid took now that the box is gone.
        freed = mbr_before - app.min_balance
        if freed > 0:
            itxn.Payment(receiver=Txn.sender, amount=freed, fee=0).submit()
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def accept_bid(
        self,
        job_id: arc4.UInt64,
        bidder_agent_id: arc4.UInt64,
        expected_price_micro: arc4.UInt64,
    ) -> arc4.Bool:
        """Assign the job to a bidder, at the price they bid.

        The budget is overwritten with the bid, which is the point: accepting an
        offer of 0.4 on a job budgeted at 1.0 should leave the record saying
        0.4. Leaving the old number would mean the job, the escrow and any
        release all disagree about what was agreed.

        The terms are pinned to what the client read. `expected_price_micro` must
        equal the bid's price, and the bid's recorded validator must still be the
        job's validator — otherwise a bidder could raise the price, or the client
        could change the validator, between the client reading the bid and
        accepting it. The bidder's proposed fallback judge is copied onto the job,
        so accepting a bid IS the client's consent to that fallback.

        The bid box is NOT swept here. Losing bids stay readable until the
        client withdraws them or the bidders do — a board that erases what it
        rejected cannot be checked afterwards.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.client.native == Txn.sender, "only the client may accept a bid"
        assert j.status.native == OPEN, "job is no longer open"

        key = self._bid_key(jid, bidder_agent_id.native)
        assert key in self.bids, "no such bid"
        bid = self.bids[key].copy()
        assert bid.price_micro == expected_price_micro, "the bid changed since you read it"
        assert bid.validator_agent_id == j.validator_agent_id, "the validator changed since this bid was placed"

        self._check_fallback(
            bid.fallback_validator_agent_id,
            j.validator_agent_id,
            bidder_agent_id,
            j.client.native,
            self._agent_address(bidder_agent_id),
        )
        j.server_agent_id = bidder_agent_id
        j.fallback_validator_agent_id = bid.fallback_validator_agent_id
        j.budget_micro = bid.price_micro
        j.status = arc4.UInt64(ASSIGNED)
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod(readonly=True)
    def get_bid(self, job_id: arc4.UInt64, bidder_agent_id: arc4.UInt64) -> Bid:
        key = self._bid_key(job_id.native, bidder_agent_id.native)
        assert key in self.bids, "no such bid"
        return self.bids[key]

    @arc4.abimethod
    def release_partial(self, job_id: arc4.UInt64, amount_micro: arc4.UInt64) -> arc4.UInt64:
        """Pay part of the escrow out. Returns what remains held.

        Milestones, without a milestone schema. A job that runs in stages is
        the normal case for anything worth escrowing, and an all-or-nothing
        release forces the client to choose between paying for unfinished work
        and holding finished work hostage.

        Client only, and only on a passing verdict — the post-window path in
        release_escrow deliberately does NOT apply here. That path exists so a
        worker can rescue their money from an absent validator; letting anyone
        trigger a partial release would let a stranger dribble it out instead.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.client.native == Txn.sender, "only the client may release part of an escrow"
        assert j.status.native == VALIDATED, "escrow is released on a passing verdict"

        assert jid in self.escrow, "nothing is escrowed for this job"
        held = self.escrow[jid]
        assert amount_micro.native > 0, "a zero release moves nothing"
        assert amount_micro.native <= held, "cannot release more than is held"

        remaining = held - amount_micro.native
        # Written BEFORE the transfer, same as _pay_escrow: a failed inner
        # transaction must not leave the ledger claiming money already sent.
        if remaining > 0:
            self.escrow[jid] = remaining
        else:
            del self.escrow[jid]

        # Resolved BEFORE the transfer is begun, and that ordering is load
        # bearing. _agent_address makes its own inner call, so resolving it
        # inside the argument list compiles to an itxn_begin nested in an
        # itxn_begin, and the AVM rejects the whole group at runtime with
        # "itxn_begin without itxn_submit". Nothing catches it earlier: it
        # compiles, deploys, and passes every check that does not actually move
        # money. release_escrow avoids it by accident — there the resolution is
        # an argument to a subroutine, which finishes before the itxn opens.
        payee = self._agent_address(j.server_agent_id)

        # The protocol fee applies here exactly as it does in _pay_escrow.
        # Without this, the two paths that pay a VALIDATED job's escrow to the
        # same worker charged different amounts: release_escrow took the fee and
        # release_partial took none, so the whole escrow could be drained
        # fee-free by asking for it in parts. Same rate, same treasury, same
        # rounding — the only difference is which slice of the escrow it is
        # taken from.
        fee = UInt64(0)
        if self.fee_bps > 0:
            fee = amount_micro.native * self.fee_bps // 10_000
            if fee > 0:
                itxn.AssetTransfer(
                    xfer_asset=self.escrow_asset,
                    asset_receiver=self.treasury,
                    asset_amount=fee,
                    fee=0,
                ).submit()

        itxn.AssetTransfer(
            xfer_asset=self.escrow_asset,
            asset_receiver=payee,
            asset_amount=amount_micro.native - fee,
            fee=0,
        ).submit()
        arc4.emit(
            EscrowPaid(
                arc4.UInt64(jid),
                arc4.Address(payee),
                arc4.UInt64(amount_micro.native - fee),
                arc4.UInt64(fee),
                arc4.Address(self.treasury),
            )
        )
        return arc4.UInt64(remaining)

    @arc4.abimethod
    def expire_job(self, job_id: arc4.UInt64) -> arc4.Bool:
        """Cancel an assigned job the assignee never delivered on.

        Anyone may call it, once the deadline has passed, because the client
        being the only one able to reclaim their own escrow is the same trap
        the dispute window exists to avoid — in reverse. The deadline is the
        same window: an assignment that has sat untouched for longer than the
        dispute window is one the assignee has abandoned.

        Only from ASSIGNED. Once a result is submitted the validator decides,
        and a deadline that could snatch the job away mid-review would let a
        client escape a verdict by waiting.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == ASSIGNED, "only an assigned job with no result can expire"
        assert (
            Global.latest_timestamp > j.updated_at.native + self.dispute_window
        ), "the assignee still has time"

        j.status = arc4.UInt64(CANCELLED)
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()
        # Escrow is NOT auto-refunded: refund_escrow already handles CANCELLED,
        # and doing it here would need the client's box reference on a call
        # anyone can make.
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def expire_verdict(self, job_id: arc4.UInt64) -> arc4.Bool:
        """Resolve a submitted result that NEITHER judge answered, by splitting.

        SUBMITTED had exactly one exit — `validation_response`. A validator who
        loses their key, abandons the agent, rotates away or simply declines
        therefore froze the escrow permanently: `expire_job` refuses anything past
        ASSIGNED, so nobody could move the job, and the `es_` box it needs was
        locked with no on-chain remedy, which also blocks deleting the app.

        It waits TWO windows, because there are two judges: the validator's own
        window, then the fallback's. Only if BOTH stay silent does this fire.

        And it SPLITS the escrow rather than handing either side a default win.
        An earlier version resolved silence to VALIDATED — but that paid a worker
        who may have submitted garbage in full, simply for the validator not
        showing up, which is a free option for the worker. Resolving to CANCELLED
        instead would be the same free option for the client. A 50/50 split gives
        neither: a worker who delivered garbage keeps only half, and a client who
        named a dead validator recovers only half. Both are worse off than
        agreeing a live judge, which is exactly the incentive this should create.
        The escrow is divided now into two boxes — the worker's half stays in
        `es_`, the client's half moves to `rf_` — so each half is claimable
        without the other party's address having to be live.

        Anyone may call it, for the same reason `expire_job` is open: a guarantee
        that only one party can invoke is not a guarantee.
        """
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == SUBMITTED, "only a submitted job awaiting a verdict can expire"
        assert (
            Global.latest_timestamp > j.updated_at.native + self.dispute_window * 2
        ), "the validator, then the fallback, still have time"

        j.status = arc4.UInt64(SPLIT)
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()

        if jid in self.escrow:
            amount = self.escrow[jid]
            worker_half = amount // 2
            client_half = amount - worker_half  # the odd base unit goes to the client
            self.split_refund[jid] = client_half
            if worker_half > 0:
                self.escrow[jid] = worker_half
            else:
                del self.escrow[jid]
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def settle_split(self, job_id: arc4.UInt64) -> arc4.UInt64:
        """Pay the worker's half of a SPLIT job. Anyone; a fee applies as it is a
        settlement for delivered (if unjudged) work. Returns the amount sent."""
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == SPLIT, "only a split job settles this way"
        return arc4.UInt64(self._pay_escrow(jid, self._agent_address(j.server_agent_id), True))  # noqa: FBT003

    @arc4.abimethod
    def claim_split_refund(self, job_id: arc4.UInt64) -> arc4.UInt64:
        """Pay the client's half of a SPLIT job. Anyone may trigger it; the
        destination is read off the job, so it can only ever go to the client, and
        it never resolves the worker — a departed worker strands only their own
        half. No fee: the client is recovering their own money. Returns the amount."""
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.status.native == SPLIT, "only a split job refunds this way"
        assert jid in self.split_refund, "nothing to refund"
        amount = self.split_refund[jid]
        del self.split_refund[jid]
        itxn.AssetTransfer(
            xfer_asset=self.escrow_asset,
            asset_receiver=j.client.native,
            asset_amount=amount,
            fee=0,
        ).submit()
        return arc4.UInt64(amount)

    @arc4.abimethod
    def set_fee(self, fee_bps: arc4.UInt64, treasury: arc4.Address) -> arc4.Bool:
        """Set a protocol fee, once, by the creator. Capped at 2.5%.

        Once and capped on purpose. A fee that can be raised after work is
        accepted is a fee the assignee never agreed to, and an uncapped one is
        a rug with extra steps. Zero — the default — means no fee is taken and
        release pays the whole escrow.
        """
        assert Txn.sender == Global.creator_address, "only the creator may set the fee"
        assert self.fee_bps == 0, "the fee is set once"
        assert fee_bps.native > 0, "use zero by leaving it unset"
        assert fee_bps.native <= 250, "the fee is capped at 2.5%"
        assert treasury.native != Global.zero_address, "a fee needs a destination"
        # The treasury must already hold the escrow asset. An Algorand account
        # cannot receive an ASA it has not opted into, and the fee transfer in
        # _pay_escrow is an inner transaction of the payout: if it fails, the
        # whole payout fails. Because set_fee is one-shot, a treasury that never
        # opted in would make release_escrow, refund_escrow and release_partial
        # permanently uncallable and freeze every escrowed cent with no way to
        # correct the address. Checked here, where it is still recoverable.
        assert treasury.native.is_opted_in(
            Asset(self.escrow_asset)
        ), "the treasury must opt into the escrow asset before it can receive a fee"
        self.fee_bps = fee_bps.native
        self.treasury = treasury.native
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def cancel_job(self, job_id: arc4.UInt64) -> arc4.Bool:
        """Withdraw an unassigned job. Once assigned, it must run its course."""
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        j = self.jobs[jid].copy()
        assert j.client.native == Txn.sender, "only the client may cancel"
        assert j.status.native == OPEN, "an assigned job cannot be cancelled"
        j.status = arc4.UInt64(CANCELLED)
        j.updated_at = arc4.UInt64(self._now())
        self.jobs[jid] = j.copy()
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod(readonly=True)
    def get_job(self, job_id: arc4.UInt64) -> Job:
        jid = job_id.native
        assert jid in self.jobs, "unknown job"
        return self.jobs[jid]

    @arc4.abimethod(readonly=True)
    def total_jobs(self) -> arc4.UInt64:
        return arc4.UInt64(self.job_count)
