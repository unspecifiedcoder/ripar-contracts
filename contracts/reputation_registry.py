"""
Reputation Registry — ERC-8004's second registry, ported to Algorand.

The rule this implements: **reputation is earned by paying, not by posting.**

ERC-8004 keeps feedback offchain and only records an authorisation onchain. That
leaves the door open to a client leaving glowing feedback for work it never
bought. Here the authorisation is bound to a settled payment: `accept_feedback`
takes the id of the x402 transfer that paid for the job, records that id, and
refuses to record it twice. A score therefore counts settlements, and cannot be
inflated by anything that did not move USDC.

What is deliberately NOT here: a star rating, a comment, or any number a human
types. Those belong offchain. What is onchain is the only part that cannot be
faked — that a specific payment happened, between a specific pair, once.
"""

from algopy import (
    ARC4Contract,
    Bytes,
    BoxMap,
    Global,
    Txn,
    UInt64,
    arc4,
    gtxn,
    subroutine,
)


class Score(arc4.Struct):
    """A server agent's record. Every field is a count of settled work."""

    agent_id: arc4.UInt64
    # Distinct settled payments received for accepted work.
    jobs_paid: arc4.UInt64
    # Total USDC settled, in base units (6 decimals).
    volume_micro: arc4.UInt64
    # Jobs a validator marked as passing. See ValidationRegistry.
    validated: arc4.UInt64
    # Jobs a validator marked as failing. Kept because hiding it would make the
    # score a marketing number rather than a record.
    disputed: arc4.UInt64
    first_at: arc4.UInt64
    last_at: arc4.UInt64


class ReputationRegistry(ARC4Contract):
    def __init__(self) -> None:
        self.identity_app = UInt64(0)
        # Which asset counts. Set at bootstrap; a transfer of anything else
        # is refused rather than silently credited.
        self.usdc_asset = UInt64(0)
        self.scores = BoxMap(UInt64, Score, key_prefix=b"sc_")
        # The ValidationRegistry, and the ONLY caller allowed to write a
        # verdict. Set separately from bootstrap because validation is deployed
        # after this contract and cannot name itself before it exists.
        self.validation_app = UInt64(0)
        # One box per job whose verdict has been written to a score, so a verdict
        # can be synced exactly once. record_validation is no longer inside
        # validation_response (an unfunded score box there could revert the whole
        # verdict and let expire_verdict force a pass); it is now driven by a
        # separate, funded, retryable call, and this set stops that call being
        # replayed to double-count validated/disputed.
        self.recorded_jobs = BoxMap(UInt64, bool, key_prefix=b"rv_")
        # There is deliberately no pd_ ledger of counted payments. One existed
        # and was never written to, so was_counted() answered 0 for every
        # payment that had in fact been counted — a reader integrating against
        # it would conclude nothing had ever settled. Replay is already
        # impossible: the payment is a transaction in THIS group, and consensus
        # rejects a duplicate txid. See accept_feedback.

    @arc4.abimethod
    def bootstrap(self, identity_app: arc4.UInt64, usdc_asset: arc4.UInt64) -> arc4.Bool:
        """Point at the Identity Registry and fix the settlement asset.

        The asset is set once and never changed, so a score always means the same
        thing. Without it accept_feedback would have to trust whatever asset a
        caller transferred, and reputation could be bought with a worthless one
        minted for the purpose.
        """
        assert Txn.sender == Global.creator_address, "creator only"
        assert self.identity_app == 0, "already bootstrapped"
        assert usdc_asset.native != 0, "the settlement asset must be set"
        self.identity_app = identity_app.native
        self.usdc_asset = usdc_asset.native
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def set_validation_app(self, validation_app: arc4.UInt64) -> arc4.Bool:
        """Name the contract allowed to write verdicts. Once, by the creator.

        Separate from bootstrap purely because of deployment order: the
        ValidationRegistry does not exist yet when this one is bootstrapped, so
        it cannot be named there.
        """
        assert Txn.sender == Global.creator_address, "only the creator may set this"
        assert self.validation_app == 0, "already set"
        assert validation_app.native > 0, "validation app id required"
        self.validation_app = validation_app.native
        return arc4.Bool(True)  # noqa: FBT003

    @subroutine
    def _touch(self, agent_id: UInt64) -> Score:
        now = Global.latest_timestamp
        if agent_id in self.scores:
            return self.scores[agent_id].copy()
        return Score(
            agent_id=arc4.UInt64(agent_id),
            jobs_paid=arc4.UInt64(0),
            volume_micro=arc4.UInt64(0),
            validated=arc4.UInt64(0),
            disputed=arc4.UInt64(0),
            first_at=arc4.UInt64(now),
            last_at=arc4.UInt64(now),
        )

    @arc4.abimethod
    def accept_feedback(
        self,
        mbr: gtxn.PaymentTransaction,
        payment: gtxn.AssetTransferTransaction,
        server_agent_id: arc4.UInt64,
        client_agent_id: arc4.UInt64,
    ) -> arc4.UInt64:
        """Credit a server agent for one settled payment. Returns its new count.

        The payment is passed as a TRANSACTION IN THIS GROUP, not as an id and an
        amount the caller supplies. That distinction is the whole point.

        The previous signature took a 32-byte id and a number, and checked only
        that the id was 32 bytes long and unseen. Nothing tied either value to a
        transfer that had actually happened, so any 32 bytes bought a point of
        reputation — an audit found two counted payments on TestNet that resolve
        to no transaction at all, one of them 32 zero bytes. The docstring
        claiming a score "cannot be inflated by anything that did not move USDC"
        was simply untrue.

        Now the amount and the id are READ OFF the transfer the AVM has already
        validated, so they cannot be fabricated: to earn a point you must move
        the asset, in the same atomic group, in the same round.
        """
        assert payment.asset_amount > 0, "a zero-value payment earns nothing"
        assert (
            payment.xfer_asset.id == self.usdc_asset
        ), "reputation is denominated in one asset; this transfer is not it"
        assert (
            server_agent_id.native != client_agent_id.native
        ), "an agent cannot pay itself into a reputation"

        # THE money must have gone to THE agent being credited.
        #
        # Reading the amount off a real transfer stopped scores being minted from
        # invented bytes, but on its own it still credited whichever id the caller
        # named. Anyone could move one microUSDC between two addresses they owned
        # and credit a stranger's agent — or, with two ids, themselves. The
        # id-inequality check above does not help: ids are not identities.
        #
        # So resolve both ends against the IdentityRegistry, which is the only
        # place an address-to-id binding is authenticated (new_agent takes the
        # owner from Txn.sender). A credit now requires the payment to have been
        # sent BY the client's registered address TO the server's.
        server_addr, _txn = arc4.abi_call[arc4.Address](
            "agent_address(uint64)address",
            server_agent_id,
            app_id=self.identity_app,
        )
        assert (
            payment.asset_receiver == server_addr.native
        ), "the payment did not go to the agent being credited"

        client_addr, _txn2 = arc4.abi_call[arc4.Address](
            "agent_address(uint64)address",
            client_agent_id,
            app_id=self.identity_app,
        )
        assert (
            payment.sender == client_addr.native
        ), "the payment did not come from the agent being credited as the client"

        # No replay ledger is needed, and keying one on the txid was in fact
        # impossible: the box name would be pd_+txid, the txid depends on the
        # group id, the group id depends on this app call, and the app call must
        # declare the box. Circular.
        #
        # It is also unnecessary. The payment is a transaction IN THIS GROUP, so
        # it is being submitted right now. Algorand rejects a duplicate txid
        # outright, so an old settlement cannot be replayed into a second credit
        # — the consensus layer already provides exactly the guarantee the box
        # was trying to reimplement, and provides it better.

        app = Global.current_application_address
        mbr_before = app.min_balance

        sid = server_agent_id.native
        s = self._touch(sid)
        s.jobs_paid = arc4.UInt64(s.jobs_paid.native + 1)
        s.volume_micro = arc4.UInt64(s.volume_micro.native + payment.asset_amount)
        s.last_at = arc4.UInt64(Global.latest_timestamp)
        self.scores[sid] = s.copy()

        # A first credit for an agent creates its score box, whose minimum
        # balance is charged to THIS app. Have the caller cover that growth so a
        # stranger cannot drain the app's own balance one score box at a time.
        assert mbr.receiver == app, "storage payment must be sent to this app"
        assert mbr.sender == Txn.sender, "you must pay for the storage you create"
        assert (
            mbr.amount >= app.min_balance - mbr_before
        ), "payment must cover the score box this credit may add"

        return arc4.UInt64(s.jobs_paid.native)

    @arc4.baremethod(allow_actions=["DeleteApplication"])
    def delete(self) -> None:
        """Creator-only teardown, so a deployment's 0.1 ALGO is not stranded.

        Blocked by the AVM while any score box remains, which is the right
        default: a registry other contracts resolve against should not vanish
        under them by accident.
        """
        assert Txn.sender == Global.creator_address, "only the creator may delete"

    @arc4.abimethod(readonly=True)
    def recent(self, agent_id: arc4.UInt64, window_secs: arc4.UInt64) -> arc4.Bool:
        """Has this agent been paid inside the last `window_secs`?

        Deliberately a boolean, not a windowed count. A real rolling window
        needs per-payment timestamps, and storing one box per payment is the
        `pd_` ledger this contract removed for being circular and unnecessary.
        Returning a count that silently meant "lifetime" would be worse than
        returning the one fact the stored data actually supports.

        Reputation here does not decay, and that is a choice worth stating: a
        payment happened or it did not, and an agent that earned trust and then
        went quiet has not become untrustworthy. What a reader usually wants to
        know is whether it is still ACTIVE, which is this.
        """
        aid = agent_id.native
        if aid not in self.scores:
            return arc4.Bool(False)  # noqa: FBT003
        last = self.scores[aid].last_at.native
        return arc4.Bool(Global.latest_timestamp <= last + window_secs.native)

    @arc4.abimethod
    def record_validation(
        self, job_id: arc4.UInt64, server_agent_id: arc4.UInt64, passed: arc4.Bool
    ) -> arc4.Bool:
        """Record a verdict against an agent's score. ValidationRegistry only.

        The caller is checked against the app id set at deployment — an address
        calling directly has a caller_application_id of 0 and is refused.

        `job_id` makes the write idempotent. The verdict is no longer recorded
        inside validation_response (an unfunded score box there could revert the
        whole call and let expire_verdict force a pass); it is driven by a
        separate, funded, retryable ValidationRegistry call, so this must reject
        a second recording of the same job or the counters could be inflated by
        replaying it.
        """
        assert self.validation_app != 0, "no validation app is set, so no verdict can be trusted"
        assert (
            Global.caller_application_id == self.validation_app
        ), "only the ValidationRegistry may record a verdict"
        jid = job_id.native
        assert jid not in self.recorded_jobs, "this job's verdict was already recorded"
        self.recorded_jobs[jid] = True
        sid = server_agent_id.native
        s = self._touch(sid)
        if passed.native:
            s.validated = arc4.UInt64(s.validated.native + 1)
        else:
            s.disputed = arc4.UInt64(s.disputed.native + 1)
        s.last_at = arc4.UInt64(Global.latest_timestamp)
        self.scores[sid] = s.copy()
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod(readonly=True)
    def get_score(self, agent_id: arc4.UInt64) -> Score:
        aid = agent_id.native
        if aid in self.scores:
            return self.scores[aid]
        now = Global.latest_timestamp
        # An unknown agent reads as all-zero rather than erroring: "no record" is
        # a real answer and the caller should render it as such.
        return Score(
            agent_id=arc4.UInt64(aid),
            jobs_paid=arc4.UInt64(0),
            volume_micro=arc4.UInt64(0),
            validated=arc4.UInt64(0),
            disputed=arc4.UInt64(0),
            first_at=arc4.UInt64(now),
            last_at=arc4.UInt64(now),
        )

    