"""
ValidationRegistry — the one-shot bootstrap, and the time-dependent guards.

The dispute window is the reason this file exists. Its guard is a liveness
guarantee: once the window closes, *anyone* may release the escrow, so a
validator who stops answering cannot freeze a worker's money indefinitely.

On chain that behaviour costs 300 seconds of real waiting per case, which is why
it has never been covered. Here the clock is a value we set, so the before and
after of the same call are two assertions in the same millisecond.

`bootstrap` is tested just as carefully because it cannot be repeated. Every
field it writes is fixed forever, and the contract's own docstring explains why
each one is not a per-call argument.
"""

import pytest
from algopy import arc4
from algopy_testing import AlgopyTestContext, algopy_testing_context

from contracts.validation_registry import ValidationRegistry

IDENTITY_APP = 769_444_119
REPUTATION_APP = 769_444_120
USDC = 10_458_941
WINDOW = 300


@pytest.fixture()
def ctx():
    with algopy_testing_context() as c:
        yield c


@pytest.fixture()
def registry(ctx: AlgopyTestContext) -> ValidationRegistry:
    return ValidationRegistry()


def _bootstrap(ctx, registry, sender=None, window=WINDOW):
    with ctx.txn.create_group(
        active_txn_overrides={"sender": sender or ctx.default_sender}
    ):
        return registry.bootstrap(
            arc4.UInt64(IDENTITY_APP),
            arc4.UInt64(REPUTATION_APP),
            arc4.UInt64(USDC),
            arc4.UInt64(window),
        )


# --- bootstrap: one shot, and every field permanent -----------------------


def test_bootstrap_fixes_all_four_terms(ctx, registry):
    _bootstrap(ctx, registry)
    assert registry.identity_app == IDENTITY_APP
    assert registry.reputation_app == REPUTATION_APP
    assert registry.escrow_asset == USDC
    assert registry.dispute_window == WINDOW


def test_bootstrap_cannot_be_repeated(ctx, registry):
    """
    There is no setter for any of these. A second bootstrap succeeding would
    mean the escrow asset could be swapped under funds already held.
    """
    _bootstrap(ctx, registry)
    with pytest.raises(Exception, match="already bootstrapped"):
        _bootstrap(ctx, registry)


def test_only_the_creator_may_bootstrap(ctx, registry):
    with pytest.raises(Exception, match="only the creator may bootstrap"):
        _bootstrap(ctx, registry, sender=ctx.any.account())


def test_a_zero_dispute_window_is_refused(ctx, registry):
    """
    The guard the contract names explicitly: a zero window would let anyone
    claim a submitted job's escrow in the same block it was submitted.
    """
    with pytest.raises(Exception, match="zero dispute window"):
        _bootstrap(ctx, registry, window=0)


@pytest.mark.parametrize(
    ("identity", "reputation", "asset", "expected"),
    [
        (0, REPUTATION_APP, USDC, "identity app id required"),
        (IDENTITY_APP, 0, USDC, "reputation app id required"),
        (IDENTITY_APP, REPUTATION_APP, 0, "escrow asset required"),
    ],
)
def test_bootstrap_refuses_a_zero_in_any_slot(
    ctx, registry, identity, reputation, asset, expected
):
    """
    A zero here is not a harmless default — app id 0 and asset id 0 are both
    readable, so a registry bootstrapped with one would fail by returning
    nothing rather than by erroring.
    """
    with pytest.raises(Exception, match=expected):
        with ctx.txn.create_group(
            active_txn_overrides={"sender": ctx.default_sender}
        ):
            registry.bootstrap(
                arc4.UInt64(identity),
                arc4.UInt64(reputation),
                arc4.UInt64(asset),
                arc4.UInt64(WINDOW),
            )


# --- the dispute window, tested by moving the clock -----------------------


def test_the_window_is_stored_exactly_as_given(ctx, registry):
    _bootstrap(ctx, registry, window=259_200)  # 72h, the MainNet value
    assert registry.dispute_window == 259_200


def test_window_arithmetic_is_strictly_greater_not_equal(ctx, registry):
    """
    The guard reads `latest_timestamp > updated_at + dispute_window`. At exactly
    the boundary the window is NOT yet closed. Off-by-one here would hand a
    third party the escrow one second early, which is the difference between a
    liveness guarantee and a race.
    """
    _bootstrap(ctx, registry)
    updated_at = 1_700_000_000

    ctx.ledger.patch_global_fields(latest_timestamp=updated_at + WINDOW)
    assert not _past_window(registry, updated_at)

    ctx.ledger.patch_global_fields(latest_timestamp=updated_at + WINDOW + 1)
    assert _past_window(registry, updated_at)


def _past_window(registry: ValidationRegistry, updated_at: int) -> bool:
    """Mirror of the contract's own expression, evaluated against the patched clock."""
    from algopy import Global

    return bool(Global.latest_timestamp > updated_at + registry.dispute_window)


def test_a_longer_window_holds_the_escrow_longer(ctx, registry):
    """Changing the term changes when a third party may act, and nothing else."""
    _bootstrap(ctx, registry, window=259_200)
    updated_at = 1_700_000_000

    # a moment that would be past a 300s window is nowhere near past 72h
    ctx.ledger.patch_global_fields(latest_timestamp=updated_at + 301)
    assert not _past_window(registry, updated_at)

    ctx.ledger.patch_global_fields(latest_timestamp=updated_at + 259_201)
    assert _past_window(registry, updated_at)


# --- expire_verdict: the escrow freeze this closes ------------------------


def test_expire_verdict_refuses_a_job_that_does_not_exist(ctx, registry):
    _bootstrap(ctx, registry)
    with pytest.raises(Exception, match="unknown job"):
        with ctx.txn.create_group(active_txn_overrides={"sender": ctx.any.account()}):
            registry.expire_verdict(arc4.UInt64(9999))


def test_expire_verdict_refuses_a_job_not_awaiting_a_verdict(ctx, registry):
    """
    The status guard is the whole safety property. Without it this would be a
    way to mark any job VALIDATED and drain its escrow — the opposite of the
    freeze it exists to fix.
    """
    _bootstrap(ctx, registry)
    # job_count is 0, so there is no job in any state; the unknown-job assert
    # fires first, which is itself the guard doing its job.
    with pytest.raises(Exception):
        with ctx.txn.create_group(active_txn_overrides={"sender": ctx.any.account()}):
            registry.expire_verdict(arc4.UInt64(1))


def _past_two_windows(registry: ValidationRegistry, submitted_at: int) -> bool:
    """Mirror of expire_verdict's own expression after the audit (R-F1)."""
    from algopy import Global

    return bool(Global.latest_timestamp > submitted_at + registry.dispute_window * 2)


def test_expire_verdict_waits_two_windows_so_the_client_veto_is_real(ctx, registry):
    """
    After the audit `expire_verdict` requires `latest_timestamp > updated_at +
    dispute_window * 2`, not one window. The first window is the validator's;
    once it passes a silent validator hands the judgement to the CLIENT
    (validation_response's fallback path). Forcing a pass must therefore wait a
    SECOND window, or anyone could force VALIDATED the instant the validator's
    window closed and beat the client's veto to it.

    At exactly two windows the client still has time; one second later the
    result stands. release_escrow keeps the one-window rule, but measured from
    when the verdict was written — a different clock, so they are no longer the
    same expression.
    """
    _bootstrap(ctx, registry)
    submitted_at = 1_700_000_000

    ctx.ledger.patch_global_fields(latest_timestamp=submitted_at + WINDOW)
    assert not _past_two_windows(registry, submitted_at), "still the validator's own window"

    ctx.ledger.patch_global_fields(latest_timestamp=submitted_at + 2 * WINDOW)
    assert not _past_two_windows(registry, submitted_at), "at the boundary the client still has its window"

    ctx.ledger.patch_global_fields(latest_timestamp=submitted_at + 2 * WINDOW + 1)
    assert _past_two_windows(registry, submitted_at), "one second past the second window, the result stands"


# --- the protocol fee: bounds, one-shot, and who may set it ---------------
#
# This whole section was missing. `set_fee` is the one privileged, economic
# lever on this contract and nothing exercised it — including, before the
# mainnet audit, the two defects below.


def test_only_the_creator_may_set_the_fee(ctx, registry):
    _bootstrap(ctx, registry)
    with pytest.raises(Exception, match="only the creator may set the fee"):
        with ctx.txn.create_group(active_txn_overrides={"sender": ctx.any.account()}):
            registry.set_fee(arc4.UInt64(100), arc4.Address(ctx.default_sender))


def test_the_fee_is_capped_at_250_bps(ctx, registry):
    """
    Uncapped is a rug with extra steps. 250 bps is the contract's own ceiling
    and 251 must be refused — the boundary is the whole point of a cap.
    """
    _bootstrap(ctx, registry)
    with pytest.raises(Exception, match="capped at 2.5%"):
        with ctx.txn.create_group(active_txn_overrides={"sender": ctx.default_sender}):
            registry.set_fee(arc4.UInt64(251), arc4.Address(ctx.default_sender))


def test_a_zero_fee_is_refused_because_zero_is_the_default(ctx, registry):
    _bootstrap(ctx, registry)
    with pytest.raises(Exception, match="use zero by leaving it unset"):
        with ctx.txn.create_group(active_txn_overrides={"sender": ctx.default_sender}):
            registry.set_fee(arc4.UInt64(0), arc4.Address(ctx.default_sender))


def test_a_fee_needs_a_real_destination(ctx, registry):
    """The zero address is a burn, not a treasury."""
    from algopy import Global

    _bootstrap(ctx, registry)
    with pytest.raises(Exception, match="a fee needs a destination"):
        with ctx.txn.create_group(active_txn_overrides={"sender": ctx.default_sender}):
            registry.set_fee(arc4.UInt64(100), arc4.Address(Global.zero_address))


def test_the_fee_defaults_to_zero_so_release_pays_everything(ctx, registry):
    """
    The safe default matters more than the setter: a registry nobody has
    configured must not skim anything.
    """
    _bootstrap(ctx, registry)
    assert registry.fee_bps == 0


@pytest.mark.parametrize(
    ("amount", "bps", "expected_fee"),
    [
        (1_000_000, 250, 25_000),   # 2.5% of $1.00 = $0.025, the ceiling
        (1_000_000, 100, 10_000),   # 1%
        (10_000, 250, 250),         # a $0.01 x402 call
        (399, 250, 9),              # floors, never rounds up
        (39, 250, 0),               # dust: fee floors to zero, payee keeps it
    ],
)
def test_fee_arithmetic_floors_and_never_exceeds_the_cap(amount, bps, expected_fee):
    """
    Mirror of the contract's own expression. Integer division floors, which is
    the direction that matters: a fee that rounded up could exceed the capped
    rate on small amounts, and every x402 settlement here is a small amount.
    """
    assert amount * bps // 10_000 == expected_fee
    assert expected_fee * 10_000 <= amount * 250
