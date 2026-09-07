"""
Identity Registry — ERC-8004's first registry, ported to Algorand.

ERC-8004 gives an agent a portable onchain identity: a numeric id, a domain
that resolves to its agent card, and the address that controls it. This is the
Algorand equivalent, with two deliberate differences from the EVM original:

  * Storage is boxes, not mappings. Boxes are paid for per byte by the app, so
    registration takes an MBR contribution from the caller rather than gas.
  * `agent_address` is checked against the actual transaction sender. On EVM
    anyone can register any address; here a registration is self-attested by
    construction, which removes a whole class of impersonation.

The reverse indexes (domain -> id, address -> id) are separate boxes because
Algorand has no iteration: without them, resolving an agent would mean walking
every id, which is not possible inside an app call.
"""

from algopy import (
    ARC4Contract,
    Account,
    BoxMap,
    Global,
    String,
    Txn,
    UInt64,
    arc4,
    gtxn,
    itxn,
    op,
    subroutine,
)


class AgentInfo(arc4.Struct):
    """One agent. `domain` hosts the agent card at /.well-known/agent.json."""

    agent_id: arc4.UInt64
    agent_domain: arc4.String
    agent_address: arc4.Address
    registered_at: arc4.UInt64
    updated_at: arc4.UInt64


class IdentityRegistry(ARC4Contract):
    def __init__(self) -> None:
        # Ids start at 1 so that 0 can mean "not found" in the reverse indexes.
        self.agent_count = UInt64(0)
        self.agents = BoxMap(UInt64, AgentInfo, key_prefix=b"ag_")
        self.by_domain = BoxMap(String, UInt64, key_prefix=b"dm_")
        self.by_address = BoxMap(Account, UInt64, key_prefix=b"ad_")
        # A proposed but unclaimed rotation: agent id -> the address invited to
        # take control. Nothing moves until that address claims it, so an identity
        # can never be pushed onto someone who did not ask for it.
        self.pending = BoxMap(UInt64, Account, key_prefix=b"pr_")

    @subroutine
    def _now(self) -> UInt64:
        return Global.latest_timestamp

    @subroutine
    def _assert_canonical_domain(self, domain: String) -> None:
        """Reject any domain that is not already in canonical form.

        Byte-exact uniqueness alone let `API.ripar.io`, `api.ripar.io.`,
        `api.ripar.io\\n` and unicode homographs all register as distinct agents
        beside the real `api.ripar.io`, so a consumer resolving domain -> id ->
        address could be pointed at a squatter. Normalising bytes on the AVM is
        expensive; enforcing that the caller already sent a canonical name is
        cheap and gives the same guarantee: lower-case ASCII, no spaces or
        control characters, no trailing dot, and short enough that `dm_`+domain
        fits the 64-byte box-key limit.
        """
        b = domain.bytes
        length = b.length
        assert length > 0, "domain required"
        assert length <= 61, "domain too long (dm_ + domain must fit 64 bytes)"
        i = UInt64(0)
        while i < length:
            c = op.getbyte(b, i)
            assert c > 32, "domain must not contain spaces or control characters"
            assert c < 127, "domain must be ascii"
            assert not (c >= 65 and c <= 90), "domain must be lower-case"
            i += 1
        assert op.getbyte(b, length - 1) != 46, "domain must not end with a dot"

    @arc4.abimethod
    def new_agent(self, mbr: gtxn.PaymentTransaction, agent_domain: arc4.String) -> arc4.UInt64:
        """Register the caller as an agent and return its new id.

        The address is taken from the sender rather than an argument: a
        registration that anyone could make on anyone's behalf is not identity,
        it is a phone book.

        The caller funds the storage. Each registration creates three boxes
        whose minimum balance is charged to THIS app's account; the docstring
        used to claim the caller contributed it but the code never took it, so
        one unfunded registration could push the app below its minimum balance
        and refuse every later registrant. `mbr` is a payment, in the same
        group, from the registrant to this app covering exactly the box storage
        it adds. deregister_agent returns it.
        """
        sender = Txn.sender

        # One identity per address, and one per domain. Re-registering should be
        # an explicit update so that a typo cannot silently orphan an id.
        assert sender not in self.by_address, "address already registered"
        assert agent_domain.native not in self.by_domain, "domain already registered"
        self._assert_canonical_domain(agent_domain.native)

        app = Global.current_application_address
        mbr_before = app.min_balance

        self.agent_count += 1
        agent_id = self.agent_count
        now = self._now()

        self.agents[agent_id] = AgentInfo(
            agent_id=arc4.UInt64(agent_id),
            agent_domain=agent_domain,
            agent_address=arc4.Address(sender),
            registered_at=arc4.UInt64(now),
            updated_at=arc4.UInt64(now),
        )
        self.by_domain[agent_domain.native] = agent_id
        self.by_address[sender] = agent_id

        # The three boxes now exist, so app.min_balance reflects their cost.
        assert mbr.receiver == app, "storage payment must be sent to this app"
        assert mbr.sender == sender, "you must pay for your own registration"
        assert (
            mbr.amount >= app.min_balance - mbr_before
        ), "payment must cover the box storage this registration adds"

        return arc4.UInt64(agent_id)

    @arc4.abimethod
    def update_agent(
        self, mbr: gtxn.PaymentTransaction, agent_id: arc4.UInt64, new_domain: arc4.String
    ) -> arc4.Bool:
        """Move an agent to a new domain. Only its own address may do this.

        `mbr` covers any GROWTH in box storage when the new domain is longer
        than the old one; a shorter domain simply returns its saving to the app.
        """
        aid = agent_id.native
        assert aid in self.agents, "unknown agent"

        info = self.agents[aid].copy()
        assert info.agent_address.native == Txn.sender, "only the agent may update itself"
        self._assert_canonical_domain(new_domain.native)
        assert new_domain.native not in self.by_domain, "domain already registered"

        app = Global.current_application_address
        mbr_before = app.min_balance

        # Drop the stale reverse index or the old domain would keep resolving to
        # this agent forever.
        del self.by_domain[info.agent_domain.native]

        info.agent_domain = new_domain
        info.updated_at = arc4.UInt64(self._now())
        self.agents[aid] = info.copy()
        self.by_domain[new_domain.native] = aid

        mbr_after = app.min_balance
        assert mbr.receiver == app, "storage payment must be sent to this app"
        assert mbr.sender == Txn.sender, "you must pay for your own update"
        if mbr_after > mbr_before:
            assert (
                mbr.amount >= mbr_after - mbr_before
            ), "payment must cover the larger domain's box storage"

        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod(readonly=True)
    def get_agent(self, agent_id: arc4.UInt64) -> AgentInfo:
        aid = agent_id.native
        assert aid in self.agents, "unknown agent"
        return self.agents[aid]

    @arc4.abimethod
    def rotate_address(self, agent_id: arc4.UInt64, new_address: arc4.Address) -> arc4.Bool:
        """PROPOSE a new controlling address. Current owner only; nothing moves yet.

        Without a way to move an identity, a compromised or lost key is terminal:
        new_agent asserts one identity per address, so the owner cannot
        re-register, and the id — with every score and job that references it — is
        stranded with a key somebody else may hold.

        But a one-step rotation let an attacker BIND their own identity onto a
        stranger's address without consent: register scam.example, rotate it onto
        a victim's payout address, and now resolve_by_address(victim) returns the
        attacker's record and the victim cannot register their own. So rotation is
        two steps: this proposes, and claim_address lets the proposed address
        accept. An address can never be handed an identity it did not ask for.
        """
        aid = agent_id.native
        assert aid in self.agents, "unknown agent"
        info = self.agents[aid].copy()
        assert info.agent_address.native == Txn.sender, "only the current address may rotate"

        new_addr = new_address.native
        assert new_addr != Global.zero_address, "cannot rotate to the zero address"
        assert new_addr != info.agent_address.native, "that is already the controlling address"
        assert new_addr not in self.by_address, "the new address already controls another agent"

        self.pending[aid] = new_addr
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def claim_address(self, agent_id: arc4.UInt64) -> arc4.Bool:
        """Accept a proposed rotation. Only the proposed address may call this,
        which is what turns a rotation into consent rather than a shove."""
        aid = agent_id.native
        assert aid in self.agents, "unknown agent"
        assert aid in self.pending, "no rotation is pending"
        assert self.pending[aid] == Txn.sender, "only the proposed address may claim"
        assert Txn.sender not in self.by_address, "the new address already controls another agent"

        info = self.agents[aid].copy()
        # The reverse index moves with control, or the OLD address would keep
        # resolving to this agent and a payer checking "does the card's address
        # match the registry" would still match a key that no longer controls it.
        del self.by_address[info.agent_address.native]
        info.agent_address = arc4.Address(Txn.sender)
        info.updated_at = arc4.UInt64(self._now())
        self.agents[aid] = info.copy()
        self.by_address[Txn.sender] = aid
        del self.pending[aid]
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def cancel_rotation(self, agent_id: arc4.UInt64) -> arc4.Bool:
        """Withdraw a proposed rotation. Current owner only."""
        aid = agent_id.native
        assert aid in self.agents, "unknown agent"
        assert self.agents[aid].agent_address.native == Txn.sender, "only the agent may cancel"
        assert aid in self.pending, "no rotation is pending"
        del self.pending[aid]
        return arc4.Bool(True)  # noqa: FBT003

    @arc4.abimethod
    def deregister_agent(self, agent_id: arc4.UInt64) -> arc4.Bool:
        """Remove your own agent, freeing the three boxes it occupies.

        Only the controlling address, because new_agent took the owner from
        Txn.sender and this has to be the same authority in reverse. Without it
        a typo'd domain is permanent: new_agent asserts one identity per
        address, so the owner cannot re-register and cannot remove the old one
        either — the id is stranded and the box minimum-balance with it.

        The id is NOT reused. agent_count only ever climbs, so a stale
        reference resolves to nothing rather than silently pointing at whoever
        registered next.
        """
        aid = agent_id.native
        assert aid in self.agents, "unknown agent"
        info = self.agents[aid].copy()
        assert info.agent_address.native == Txn.sender, "only the controlling address may deregister"

        app = Global.current_application_address
        mbr_before = app.min_balance

        del self.by_domain[info.agent_domain.native]
        del self.by_address[info.agent_address.native]
        del self.agents[aid]
        # A proposed-but-unclaimed rotation would otherwise outlive the agent.
        if aid in self.pending:
            del self.pending[aid]

        # Return the storage deposit new_agent took. The boxes are gone, so
        # min_balance has dropped by what registration (and any pending) held.
        freed = mbr_before - app.min_balance
        if freed > 0:
            itxn.Payment(receiver=Txn.sender, amount=freed, fee=0).submit()

        return arc4.Bool(True)  # noqa: FBT003

    @arc4.baremethod(allow_actions=["DeleteApplication"])
    def delete(self) -> None:
        """Creator-only teardown, so a deployment's minimum balance is not lost.

        Every app permanently locks 0.1 ALGO of the creator's minimum balance,
        and without a handler here that is unreclaimable — four failed create
        attempts during one afternoon stranded 0.4 ALGO in apps nobody can
        reach. That is the whole reason this exists.

        Boxes are NOT swept: the AVM will not let this app be deleted while any
        remain, so a live registry cannot be pulled out from under its readers
        by accident. Deregister the agents first, or this simply fails.
        """
        assert Txn.sender == Global.creator_address, "only the creator may delete"

    @arc4.abimethod(readonly=True)
    def agent_address(self, agent_id: arc4.UInt64) -> arc4.Address:
        """Just the controlling address. Exists for cross-contract callers.

        `get_agent` returns the whole record, including a dynamic string, which
        another contract would have to decode to reach the one field it wants.
        This returns a fixed 32 bytes, so ReputationRegistry can bind a payment
        to the agent it credits in a single inner call.

        Asserts rather than returning the zero address: a caller that treated
        "not found" as an address would compare it against a real one and get a
        silent mismatch instead of a reason.
        """
        aid = agent_id.native
        assert aid in self.agents, "unknown agent"
        return self.agents[aid].agent_address

    @arc4.abimethod(readonly=True)
    def resolve_by_domain(self, agent_domain: arc4.String) -> arc4.UInt64:
        """0 means not found — callers must check rather than trust the id."""
        d = agent_domain.native
        if d in self.by_domain:
            return arc4.UInt64(self.by_domain[d])
        return arc4.UInt64(0)

    @arc4.abimethod(readonly=True)
    def resolve_by_address(self, agent_address: arc4.Address) -> arc4.UInt64:
        a = agent_address.native
        if a in self.by_address:
            return arc4.UInt64(self.by_address[a])
        return arc4.UInt64(0)

    @arc4.abimethod(readonly=True)
    def total_agents(self) -> arc4.UInt64:
        return arc4.UInt64(self.agent_count)
