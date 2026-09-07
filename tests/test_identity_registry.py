"""
IdentityRegistry, tested without a chain.

Every assertion below was previously provable only by deploying the contract and
spending ALGO against it — the attack suite in `deploy-v2.mjs` is a real network
run, so the guards it covers cost money and a LocalNet to exercise. These run in
milliseconds against `algorand-python-testing`, which executes the same Algorand
Python source the compiler consumes.

That distinction matters for the refusal cases in particular. "The contract
rejects this" is the half of the behaviour most likely to rot silently, because
nothing downstream breaks when a guard stops firing — the call simply starts
succeeding.
"""

import pytest
from algopy import OnCompleteAction, arc4
from algopy_testing import AlgopyTestContext, algopy_testing_context

from contracts.identity_registry import IdentityRegistry


@pytest.fixture()
def ctx():
    with algopy_testing_context() as c:
        yield c


@pytest.fixture()
def registry(ctx: AlgopyTestContext) -> IdentityRegistry:
    return IdentityRegistry()


def _app_addr(ctx, registry):
    return ctx.ledger.get_app(registry).address


def _register(ctx, registry, sender, domain: str, mbr_receiver=None, mbr_amount=1_000_000):
    """Register, attaching the storage payment new_agent now requires.

    The emulator does not model the box minimum-balance delta (min_balance stays
    put across box creation), so the exact-amount half of the guard can only be
    proven on chain; what these exercise is that a payment to THIS app from the
    caller is required, and every other rule around it.
    """
    app = _app_addr(ctx, registry)
    pay = ctx.any.txn.payment(
        sender=sender, receiver=mbr_receiver or app, amount=mbr_amount
    )
    call = ctx.any.txn.application_call(app_id=ctx.ledger.get_app(registry), sender=sender)
    with ctx.txn.create_group(gtxns=[pay, call], active_txn_index=1):
        return registry.new_agent(pay, arc4.String(domain))


def _update(ctx, registry, sender, agent_id, domain: str):
    app = _app_addr(ctx, registry)
    pay = ctx.any.txn.payment(sender=sender, receiver=app, amount=1_000_000)
    call = ctx.any.txn.application_call(app_id=ctx.ledger.get_app(registry), sender=sender)
    with ctx.txn.create_group(gtxns=[pay, call], active_txn_index=1):
        return registry.update_agent(pay, agent_id, arc4.String(domain))


# --- registration ---------------------------------------------------------


def test_first_registration_takes_id_one(ctx, registry):
    agent_id = _register(ctx, registry, ctx.default_sender, "first.example")
    assert agent_id.native == 1
    assert registry.agent_count == 1


def test_ids_are_issued_sequentially_and_never_reused(ctx, registry):
    a = ctx.any.account()
    b = ctx.any.account()
    assert _register(ctx, registry, a, "a.example").native == 1
    assert _register(ctx, registry, b, "b.example").native == 2

    # Deregistering agent 1 must not free its id for reuse: a third
    # registration takes 3, not 1. Reused ids would let a new owner inherit
    # another agent's reputation history.
    with ctx.txn.create_group(active_txn_overrides={"sender": a}):
        registry.deregister_agent(arc4.UInt64(1))
    c = ctx.any.account()
    assert _register(ctx, registry, c, "c.example").native == 3


def test_the_registered_address_is_the_sender_not_an_argument(ctx, registry):
    """The whole anti-impersonation claim rests on this."""
    caller = ctx.any.account()
    agent_id = _register(ctx, registry, caller, "sender.example")
    with ctx.txn.create_group(active_txn_overrides={"sender": caller}):
        stored = registry.agent_address(agent_id)
    assert stored.native == caller


# --- registration refusals ------------------------------------------------


def test_one_identity_per_address(ctx, registry):
    caller = ctx.any.account()
    _register(ctx, registry, caller, "one.example")
    with pytest.raises(Exception, match="address already registered"):
        _register(ctx, registry, caller, "two.example")


def test_a_domain_cannot_be_claimed_twice(ctx, registry):
    _register(ctx, registry, ctx.any.account(), "taken.example")
    with pytest.raises(Exception, match="domain already registered"):
        _register(ctx, registry, ctx.any.account(), "taken.example")


def test_an_empty_domain_is_refused(ctx, registry):
    with pytest.raises(Exception, match="domain required"):
        _register(ctx, registry, ctx.any.account(), "")


# --- domain canonicalisation (audit R-9) ----------------------------------
#
# Byte-exact uniqueness alone let API.ripar.io, api.ripar.io. and unicode
# homographs each register beside the real api.ripar.io, so a consumer resolving
# domain -> id -> address could be pointed at a squatter. Registration now
# refuses anything not already in canonical form.


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("API.ripar.io", "lower-case"),
        ("Api.Ripar.Io", "lower-case"),
        ("api.ripar.io.", "must not end with a dot"),
        ("api ripar.io", "spaces or control"),
        ("api.ripar.io\n", "spaces or control"),
        ("a" * 62, "too long"),
    ],
)
def test_non_canonical_domains_are_refused(ctx, registry, domain, expected):
    with pytest.raises(Exception, match=expected):
        _register(ctx, registry, ctx.any.account(), domain)


def test_a_canonical_domain_at_the_length_limit_is_accepted(ctx, registry):
    """61 bytes is the ceiling: dm_ + domain must fit a 64-byte box key."""
    assert _register(ctx, registry, ctx.any.account(), "a" * 61).native == 1


def test_the_storage_payment_must_be_sent_to_this_app(ctx, registry):
    """A payment to somewhere else does not fund the boxes this app creates."""
    caller = ctx.any.account()
    elsewhere = ctx.any.account()
    with pytest.raises(Exception, match="storage payment must be sent to this app"):
        _register(ctx, registry, caller, "wrong.payee.example", mbr_receiver=elsewhere)


# --- update ---------------------------------------------------------------


def test_only_the_agent_may_update_itself(ctx, registry):
    owner = ctx.any.account()
    stranger = ctx.any.account()
    agent_id = _register(ctx, registry, owner, "owned.example")

    with pytest.raises(Exception, match="only the agent may update itself"):
        _update(ctx, registry, stranger, agent_id, "stolen.example")


def test_update_cannot_take_a_domain_someone_else_holds(ctx, registry):
    a = ctx.any.account()
    b = ctx.any.account()
    first = _register(ctx, registry, a, "a.example")
    _register(ctx, registry, b, "b.example")

    with pytest.raises(Exception, match="domain already registered"):
        _update(ctx, registry, a, first, "b.example")


def test_updating_an_unknown_agent_is_refused(ctx, registry):
    with pytest.raises(Exception, match="unknown agent"):
        _update(ctx, registry, ctx.any.account(), arc4.UInt64(9999), "ghost.example")


# --- address rotation -----------------------------------------------------


def test_rotation_moves_control_and_keeps_the_id(ctx, registry):
    old = ctx.any.account()
    new = ctx.any.account()
    agent_id = _register(ctx, registry, old, "rotate.example")

    # Two steps now: the owner proposes, and nothing moves until the new address
    # claims it. Control has NOT moved after the proposal alone.
    with ctx.txn.create_group(active_txn_overrides={"sender": old}):
        registry.rotate_address(agent_id, arc4.Address(new))
    with ctx.txn.create_group(active_txn_overrides={"sender": new}):
        assert registry.agent_address(agent_id).native == old

    with ctx.txn.create_group(active_txn_overrides={"sender": new}):
        registry.claim_address(agent_id)

    with ctx.txn.create_group(active_txn_overrides={"sender": new}):
        assert registry.agent_address(agent_id).native == new
        # the reverse index must follow, or the agent becomes unresolvable
        assert registry.resolve_by_address(arc4.Address(new)).native == agent_id.native
        assert registry.resolve_by_address(arc4.Address(old)).native == 0


def test_rotation_needs_the_new_address_to_consent(ctx, registry):
    """The F4 fix: a one-step rotation let an attacker bind their identity onto a
    victim's address without consent. Now a proposal alone changes nothing, so
    the victim is never squatted and can still register."""
    attacker = ctx.any.account()
    victim = ctx.any.account()
    bad = _register(ctx, registry, attacker, "scam.example")
    with ctx.txn.create_group(active_txn_overrides={"sender": attacker}):
        registry.rotate_address(bad, arc4.Address(victim))
    with ctx.txn.create_group(active_txn_overrides={"sender": victim}):
        # the victim is untouched: still unregistered, address still free
        assert registry.resolve_by_address(arc4.Address(victim)).native == 0
    assert _register(ctx, registry, victim, "victim.example").native == 2


def test_only_the_proposed_address_may_claim(ctx, registry):
    owner, new, thief = ctx.any.account(), ctx.any.account(), ctx.any.account()
    aid = _register(ctx, registry, owner, "claimguard.example")
    with ctx.txn.create_group(active_txn_overrides={"sender": owner}):
        registry.rotate_address(aid, arc4.Address(new))
    with pytest.raises(Exception, match="only the proposed address may claim"):
        with ctx.txn.create_group(active_txn_overrides={"sender": thief}):
            registry.claim_address(aid)


def test_the_owner_can_cancel_a_pending_rotation(ctx, registry):
    owner, new = ctx.any.account(), ctx.any.account()
    aid = _register(ctx, registry, owner, "cancel.example")
    with ctx.txn.create_group(active_txn_overrides={"sender": owner}):
        registry.rotate_address(aid, arc4.Address(new))
    with ctx.txn.create_group(active_txn_overrides={"sender": owner}):
        registry.cancel_rotation(aid)
    with pytest.raises(Exception, match="no rotation is pending"):
        with ctx.txn.create_group(active_txn_overrides={"sender": new}):
            registry.claim_address(aid)


def test_only_the_current_address_may_rotate(ctx, registry):
    owner = ctx.any.account()
    stranger = ctx.any.account()
    agent_id = _register(ctx, registry, owner, "guard.example")

    with pytest.raises(Exception, match="only the current address may rotate"):
        with ctx.txn.create_group(active_txn_overrides={"sender": stranger}):
            registry.rotate_address(agent_id, arc4.Address(stranger))


def test_cannot_rotate_onto_an_address_that_controls_another_agent(ctx, registry):
    a = ctx.any.account()
    b = ctx.any.account()
    first = _register(ctx, registry, a, "x.example")
    _register(ctx, registry, b, "y.example")

    with pytest.raises(Exception, match="already controls another agent"):
        with ctx.txn.create_group(active_txn_overrides={"sender": a}):
            registry.rotate_address(first, arc4.Address(b))


def test_rotating_to_the_same_address_is_refused(ctx, registry):
    owner = ctx.any.account()
    agent_id = _register(ctx, registry, owner, "same.example")
    with pytest.raises(Exception, match="already the controlling address"):
        with ctx.txn.create_group(active_txn_overrides={"sender": owner}):
            registry.rotate_address(agent_id, arc4.Address(owner))


def test_rotating_to_the_zero_address_is_refused(ctx, registry):
    """Rotating an identity onto the zero address makes it permanently
    unresolvable and strands anything referencing it — a footgun, not a move."""
    from algopy import Global

    owner = ctx.any.account()
    agent_id = _register(ctx, registry, owner, "zero.example")
    with pytest.raises(Exception, match="cannot rotate to the zero address"):
        with ctx.txn.create_group(active_txn_overrides={"sender": owner}):
            registry.rotate_address(agent_id, arc4.Address(Global.zero_address))


# --- deregistration -------------------------------------------------------


def test_only_the_controlling_address_may_deregister(ctx, registry):
    owner = ctx.any.account()
    stranger = ctx.any.account()
    agent_id = _register(ctx, registry, owner, "mine.example")

    with pytest.raises(Exception, match="only the controlling address may deregister"):
        with ctx.txn.create_group(active_txn_overrides={"sender": stranger}):
            registry.deregister_agent(agent_id)


def test_deregistration_frees_the_domain_and_the_address(ctx, registry):
    owner = ctx.any.account()
    agent_id = _register(ctx, registry, owner, "freed.example")
    with ctx.txn.create_group(active_txn_overrides={"sender": owner}):
        registry.deregister_agent(agent_id)

    # both reverse indexes must be cleared, or the domain is burned forever
    later = ctx.any.account()
    assert _register(ctx, registry, later, "freed.example").native == 2
    # and the original owner can register again
    assert _register(ctx, registry, owner, "again.example").native == 3


# --- resolution -----------------------------------------------------------


def test_resolution_round_trips_by_domain_and_address(ctx, registry):
    owner = ctx.any.account()
    agent_id = _register(ctx, registry, owner, "round.example")
    with ctx.txn.create_group(active_txn_overrides={"sender": owner}):
        assert registry.resolve_by_domain(arc4.String("round.example")).native == agent_id.native
        assert registry.resolve_by_address(arc4.Address(owner)).native == agent_id.native


def test_unknown_lookups_answer_zero_rather_than_failing(ctx, registry):
    """
    Zero is the contract's 'no such record'. It must be an answer, not an
    error — callers are documented to check it, and an exception here would
    make a negative lookup indistinguishable from an unreachable node.
    """
    with ctx.txn.create_group(active_txn_overrides={"sender": ctx.any.account()}):
        assert registry.resolve_by_domain(arc4.String("nobody.example")).native == 0
        assert registry.resolve_by_address(arc4.Address(ctx.any.account())).native == 0


def test_reading_an_unknown_agent_is_an_error(ctx, registry):
    """get_agent differs from resolve_*: there is no sentinel struct to return."""
    with pytest.raises(Exception, match="unknown agent"):
        with ctx.txn.create_group(active_txn_overrides={"sender": ctx.any.account()}):
            registry.get_agent(arc4.UInt64(4242))


# --- deletion -------------------------------------------------------------


def test_only_the_creator_may_delete(ctx, registry):
    """
    `delete` is a baremethod gated on DeleteApplication, so the on-completion
    has to be set or the call never reaches the guard at all — the harness
    fails earlier with an unrelated error and the test would pass for the
    wrong reason.
    """
    deleting = {"on_completion": OnCompleteAction.DeleteApplication}

    with pytest.raises(Exception, match="only the creator may delete"):
        with ctx.txn.create_group(
            active_txn_overrides={"sender": ctx.any.account(), **deleting}
        ):
            registry.delete()


def test_the_creator_may_delete(ctx, registry):
    """The positive half — a guard that refuses everyone is also broken."""
    with ctx.txn.create_group(
        active_txn_overrides={"sender": ctx.default_sender,
                              "on_completion": OnCompleteAction.DeleteApplication}
    ):
        registry.delete()
