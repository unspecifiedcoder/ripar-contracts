# ripar-contracts

The on-chain half of [Ripar](https://ripar.io): three registries that give an
agent an identity, a reputation nobody can type by hand, and an escrow that pays
out on a verdict.

They are a port of the [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)
identity / reputation / validation triad to Algorand, written in Algorand Python
and compiled with PuyaPy.

## Deployed

**TestNet — live and in use**

| Registry | App ID | What it holds |
| --- | --- | --- |
| Identity | [`770382913`](https://lora.algokit.io/testnet/application/770382913) | one `ag_` box per agent: id, domain, controlling address |
| Reputation | [`770382914`](https://lora.algokit.io/testnet/application/770382914) | one `sc_` box per agent: jobs paid, volume, verdicts |
| Validation | [`770382915`](https://lora.algokit.io/testnet/application/770382915) | jobs, bids and escrow, settled in USDC `10458941` |

**MainNet — not deployed yet.** This section will carry the app ids and an
explorer link when it is. It does not carry placeholders in the meantime.

## The escrow, end to end

```
post_job ──▶ place_bid ──▶ accept_bid ──▶ fund_job ──▶ submit_result
                                                            │
                                              validation_response
                                                            │
                                            ┌───────────────┴───────────────┐
                                       VALIDATED                       DISPUTED
                                            │                               │
                                    release_escrow                  refund_escrow
                                     (or release_partial)            (to the client)
```

Money only moves on the last step, and only in the direction the verdict points.

### The liveness escape

A validator who stops answering must not be able to freeze a worker's money.
Once `dispute_window` has passed since a result was submitted, **anyone** may
call `expire_verdict` to mark the job validated, and **anyone** may then call
`release_escrow`. The worker does not need the validator's cooperation to be paid.

TestNet runs a 300-second window so the test suite does not have to wait.
MainNet is configured for 259200 seconds (72 hours).

## The protocol fee

**Currently zero. Nothing is being skimmed.** `fee_bps` is `0` and `treasury` is
the zero address on the live registry — you can verify that yourself in the
global state at the link above.

If it is ever set:

- **`set_fee(fee_bps, treasury)` is creator-only and works exactly once.** There is no setter to raise it later. A fee that can move after work is accepted is a fee the assignee never agreed to.
- **It is capped at 250 basis points (2.5%).** The contract refuses 251.
- **It is taken on release, not on funding.** The client escrows exactly the budget they agreed to; the fee comes out of the settlement.
- **It applies identically to `release_escrow` and `release_partial`.** (It did not, until an audit found the whole escrow could be drained fee-free by asking for it in parts.)
- **The treasury must already hold the escrow asset.** An Algorand account cannot receive an ASA it has not opted into, and the fee transfer is an inner transaction of the payout — so a treasury that never opted in would make every payout fail forever, unfixably, because `set_fee` is one-shot. The contract now checks this before accepting the address.

Every payout emits an ARC-28 `EscrowPaid` event carrying the job id, the payee,
the amount paid and the fee taken, so treasury income is attributable to a job
without replaying box state.

## Getting what you are owed

There is no "withdraw" button, because Ripar never holds your money.

- **For a paid HTTP call (x402):** settlement is a direct USDC transfer from the caller to your payout address. It is already yours the moment the transaction confirms. Nothing to withdraw.
- **For an escrowed job:** the client calls `release_escrow` on a passing verdict, or `release_partial` for a milestone. If the validator has gone quiet, wait out the dispute window and call `expire_verdict` then `release_escrow` yourself — neither requires the client or the validator.
- **For a bid you no longer want:** `withdraw_bid`, callable only by the bidder.

## Build and test

```bash
python -m puyapy contracts/validation_registry.py \
  contracts/identity_registry.py \
  contracts/reputation_registry.py \
  --out-dir "$(pwd)/contracts/artifacts"

pytest tests/          # 43 tests, no chain required
```

The suite runs against `algorand-python-testing`, so the time-dependent guards —
the dispute window, `expire_verdict` — are asserted on both sides of the boundary
in the same millisecond instead of costing a real 300 seconds each.

**`--out-dir` must be absolute.** PuyaPy resolves it relative to the source file,
so a relative path silently writes to `contracts/contracts/artifacts/` and leaves
the real artifacts stale — which is how a deploy can ship a contract that does
not match the source it was audited from.

## Verifying you are deploying what was audited

The build is reproducible. Compiling the sources in `contracts/` produces
bytecode that hashes identically to the artifacts committed in
`contracts/artifacts/`:

| contract | approval sha256[:16] |
| --- | --- |
| IdentityRegistry | `81b4260127d8ac3e` |
| ReputationRegistry | `86fe00227823828b` |
| ValidationRegistry | `b29f2d040a1707b4` |

These are the hashes of the **current, audited** source. The apps live on TestNet
(`770382913` / `770382914` / `770382915`) were built from the PRE-audit source and
hash `b14ffe7001b39a89` / `14d3857c38bcf76d` / `18009c6c862a295b` — so the committed
contracts are now **ahead of what is deployed and need redeploying** before those
app ids carry the audited logic.

```bash
python -m puyapy contracts/*.py --out-dir "$(pwd)/build"
# then compare byteCode.approval in build/*.arc56.json against contracts/artifacts/
```

As of the 2026-09 audit the deployed registries **no longer match** the committed
source: `770382913` / `770382914` / `770382915` were built before the audit, and
the fixes below changed both the ABI and the approval programs. They still answer
reads with their pre-audit behaviour until a redeploy replaces them.

That matters because a deployed app which no longer matches its source is not
something you can detect by reading either one. The generation before them —
`769444119` / `769444120` / `769444121` — is in exactly that state. It predates
the audit below, its ValidationRegistry hashes `9d7797273fa2ba16` rather than
`18009c6c862a295b`, and the contract declares no `UpdateApplication`, so it
could not be corrected in place. It was replaced rather than patched.

**It is still on chain and still answers reads.** A superseded Algorand app is
not deleted, so anything still pointing at `769444121` will look like it is
working. **Do not call `set_fee` on it**: a treasury that has not opted into the
escrow asset would make every payout on that app fail permanently, and the
one-shot setter means there is no second chance.

## What the audit changed

Three defects in the fee mechanism, all found before any of it was set, and all
fixed in the source these artifacts are built from:

1. **`set_fee` could freeze every escrow, forever.** It checked only that the
   treasury was not the zero address. An Algorand account cannot receive an ASA
   it has not opted into, and the fee transfer is an inner transaction of the
   payout — so a treasury that never opted in makes `release_escrow`,
   `refund_escrow` and `release_partial` all fail. Because `set_fee` runs once,
   the address could never be corrected. Now guarded with `is_opted_in`.

2. **The fee could be bypassed entirely.** `release_partial` took no fee while
   `_pay_escrow` did, and both pay a VALIDATED job's escrow to the same worker —
   so the whole escrow could be drained fee-free by asking for it in parts.

3. **Nothing emitted events.** The transfers were always on chain, but which job
   a transfer settled, and how much of it was fee, existed only as a box diff.

The fee mechanism had **zero test coverage** before this. It now has ten tests
covering creator-only, one-shot, the 250 bps ceiling at its boundary, zero-fee
and zero-address rejection, the safe default, and the flooring arithmetic down
to dust amounts. The suite went from 33 to 43.

## 2026-09 audit

A second, broader audit followed the fee work. Its fixes are in the source these
artifacts are built from, so **the committed contracts are ahead of the deployed
`770382913` / `770382914` / `770382915` apps and need redeploying** before those
app ids carry them.

- **The caller funds box storage now.** Creating an agent, a job, a bid or an
  escrow used to draw the box minimum balance from the *app* account. One
  registration against a drained app account bricked the registry permanently —
  a DoS one write from full. Every box-creating method now takes a leading
  payment and the caller funds their own box.
- **The verdict write is decoupled from `validation_response`.** Judging a job no
  longer inner-calls the reputation registry, so a starved or wedged reputation
  app can no longer make a valid verdict fail. The score is synced separately by
  `record_job_verdict`, which anyone can fund and call once a job is decided.
- **Escrow is capped at the budget.** Funding a job with more than the agreed
  budget no longer over-escrows; the excess is refunded to the client.
- **Domains must be canonical.** A domain is accepted only in its canonical form,
  so the same name cannot be registered twice under different spellings.
- **A client can reclaim a stranded escrow.** If a job is VALIDATED but the worker
  cannot be paid, the client can `reclaim_stranded` after four dispute windows
  rather than losing the escrow forever.
- **Refunds no longer pay a protocol fee.** The fee is taken only on a real
  payout to a worker; a `refund_escrow` back to the client is fee-free.
- **The ops scripts were fixed too.** `reclaim.mjs` now derives its keep-set from
  `DEPLOYED.json` instead of a hard-coded id that had gone stale (and would have
  deleted the live registry), and the deploy scripts refuse to bootstrap a
  sub-hour dispute window on a public network.

**The escrow judging was redesigned, because the first fix was itself
exploitable.** A red-team pass on the fix above found it had only moved the free
option, not closed it: giving the client a fallback judge let the client sit on
delivered work and reject it for nothing, freezing a paid worker exactly as an
absent validator would. It was replaced with a symmetric design. Whoever
initiates the pairing names a fallback judge — the client in `assign_job`, the
bidder in `place_bid` — and the other side consents by committing to it on
accept. `validation_response` now takes an `as_validator` argument naming the id
the caller is acting as (the validator, or the fallback once the validator's
window has passed). If **both** judges stay silent, `expire_verdict` no longer
resolves to a full release for either party: the job moves to a new `SPLIT`
status (6) that divides the escrow 50/50 into two boxes — the worker's half in
`es_`, the client's half in `rf_` — claimed by `settle_split` and
`claim_split_refund`. Neither side wins by default.

One residual is worth stating plainly: a worker can still route the fallback to a
second agent it controls, and on chain that is indistinguishable from an
independent judge. That is why the fallback is a **visible field** named at
pairing time rather than a hidden default.

For deployments that want that residual closed, there is now an optional
**protocol arbiter**: `set_arbiter(agent_id)` (creator only). When set, the
arbiter is the second judge for **every** job — it supersedes any party-named
fallback, so a worker's own puppet fallback can no longer act; the arbiter, a
trusted independent judge, does, and a job neither the validator nor the arbiter
answers still falls through to the 50/50 `SPLIT`. It is off by default
(`arbiter_agent_id == 0`) and, unlike the fee, it is not one-shot — an arbiter key
can be rotated. That it can be changed is exactly why it is a **trusted role**: a
deployment that cannot assume an honest creator should leave it unset and rely on
the named fallback and the SPLIT backstop.

## Deploying

```bash
RIPAR_CONFIG=mainnet.json \
RIPAR_NETWORK=mainnet \
ALGOD_URL=https://mainnet-api.algonode.cloud \
node deploy-mainnet.mjs
```

Copy `mainnet-config.example.json` to `~/.ripar/mainnet.json` and fill in the
mnemonic yourself. **The default config is a TestNet one** carrying asset
`10458941` and a 300-second window; `bootstrap` takes both permanently and cannot
be re-run, so pointing it at MainNet would mint a registry settling in an asset
nobody holds on that chain.

Measured cost to deploy all three: **~1.41 ALGO** (1.206 of that is app-creation
minimum balance — measured on chain, not estimated from the schema, because the
schema formula under-counts it).
