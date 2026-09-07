/**
 * Deploy the three registries with the authorisation holes closed, then prove
 * they are closed by attacking them.
 *
 * The three defects, all confirmed by an adversarial audit against the live
 * TestNet deployment:
 *
 *   ReputationRegistry.accept_feedback  read the amount off a real transfer but
 *     never checked WHERE it went, so one microUSDC moved between two addresses
 *     you own credited any agent id you named.
 *   ValidationRegistry.validation_response  authorised with
 *     `client == sender OR validator_agent_id > 0`, which is vacuous whenever a
 *     validator is named: any address could mark any job validated.
 *   ValidationRegistry.submit_result  did not check the submitter at all, with
 *     a comment saying the SDK would. A check in the SDK is not a check.
 *
 * All three now resolve the address through the IdentityRegistry by inner call,
 * because that is the one place an address-to-id binding is authenticated —
 * new_agent takes the owner from Txn.sender.
 *
 * The negative tests at the end are the point of this script. A deployment that
 * merely succeeds proves nothing about who is allowed to write.
 */
import algosdk from "algosdk";
import fs from "node:fs";
import { configPath } from "./config-path.mjs";

const cfg = JSON.parse(fs.readFileSync(configPath("testnet-e2e.json"), "utf8"));
const algod = new algosdk.Algodv2(
  process.env.ALGOD_TOKEN ?? "",
  process.env.ALGOD_URL ?? "https://testnet-api.algonode.cloud",
  process.env.ALGOD_PORT ?? ""
);

const deployer = algosdk.mnemonicToSecretKey(cfg.merchant.mnemonic);
const other = algosdk.mnemonicToSecretKey(cfg.payer.mnemonic); // the attacker
const ASSET = cfg.assetId;

// The dispute window is one-shot: `bootstrap` takes it permanently. A 20-second
// production window lets ANYONE call expire_verdict then release_escrow ~40s
// after a result is submitted, draining the escrow before the client or a real
// validator can look at the work. So on a public chain it is not allowed to
// default and it is not allowed to be short — refuse to start. LocalNet is
// exempt: its blocks are ~25s apart, so this attack suite must use a window of
// seconds for the expiry paths to be observable inside one run.
const isLocalNet =
  /localhost|127\.0\.0\.1|:4001\b/.test(process.env.ALGOD_URL ?? "") ||
  /local/i.test(cfg.network ?? "");
if (!isLocalNet) {
  if (cfg.disputeWindowSecs == null) {
    throw new Error(
      "disputeWindowSecs is missing from the config. On a public network it must be set " +
      "explicitly (MainNet uses 259200 = 72h); a defaulted 20s window lets anyone drain " +
      "escrow ~40s after a result is submitted."
    );
  }
  if (Number(cfg.disputeWindowSecs) < 3600) {
    throw new Error(
      `disputeWindowSecs is ${cfg.disputeWindowSecs}s, below the 3600s (1h) floor for a ` +
      "public network. bootstrap takes it permanently, so a short window cannot be corrected " +
      "— only redeployed."
    );
  }
}
const DISPUTE_WINDOW = Number(cfg.disputeWindowSecs ?? 20);

const art = (name) =>
  JSON.parse(fs.readFileSync(`contracts/artifacts/${name}.arc56.json`, "utf8"));

const compile = async (teal) => {
  const r = await algod.compile(Buffer.from(teal, "utf8")).do();
  return new Uint8Array(Buffer.from(r.result, "base64"));
};

async function deploy(name) {
  const a = art(name);
  // Compile the TEAL source. arc56's `byteCode` field is ALREADY assembled, so
  // feeding it back to /compile assembles base64 as if it were source and
  // returns "unknown opcode" for every byte.
  const approval = await compile(fs.readFileSync(`contracts/artifacts/${name}.approval.teal`, "utf8"));
  const clear = await compile(fs.readFileSync(`contracts/artifacts/${name}.clear.teal`, "utf8"));

  const sp = await algod.getTransactionParams().do();
  const g = a.state?.schema?.global ?? { ints: 8, bytes: 8 };
  const txn = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    suggestedParams: sp,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    approvalProgram: approval,
    clearProgram: clear,
    numGlobalInts: (g.ints ?? 0) + 2,
    numGlobalByteSlices: (g.bytes ?? 0) + 2,
    numLocalInts: 0,
    numLocalByteSlices: 0,
    // A compiled program is capped at 2048 bytes per page, and each extra page
    // costs another 0.1 ALGO of the creator's minimum balance — so ask for
    // exactly what this program needs and no more. ValidationRegistry outgrew
    // one page the moment bidding and milestones went in; the failure is
    // "approval program too long" from the node, which the compiler does not
    // warn about.
    extraPages: Math.min(3, Math.floor(approval.length / 2048)),
  });
  const signed = txn.signTxn(deployer.sk);
  const { txid } = await algod.sendRawTransaction(signed).do();
  const res = await algosdk.waitForConfirmation(algod, txid, 6);
  const appId = Number(res.applicationIndex);
  console.log(`  ${name.padEnd(19)} app ${appId}`);
  return appId;
}

/** Boxes come out of the APP account's balance, not the caller's. An unfunded
 *  app fails with a bare "account <addr>" error that names no cause. */
async function fund(appId, algos) {
  const sp = await algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployer.addr,
    receiver: algosdk.getApplicationAddress(appId).toString(),
    amount: Math.round(algos * 1e6),
    suggestedParams: sp,
  });
  const { txid } = await algod.sendRawTransaction(txn.signTxn(deployer.sk)).do();
  await algosdk.waitForConfirmation(algod, txid, 6);
}

const M = (name, args, ret) =>
  new algosdk.ABIMethod({ name, args, returns: { type: ret } });

async function call({ appId, method, args, sender = deployer, boxes = [], fee = 3000, foreignApps = [], assets = [], accounts = [], extra = [] }) {
  const sp = await algod.getTransactionParams().do();
  const atc = new algosdk.AtomicTransactionComposer();
  const signer = algosdk.makeBasicAccountTransactionSigner(sender);
  for (const t of extra) atc.addTransaction(t);
  atc.addMethodCall({
    appID: appId,
    method,
    methodArgs: args,
    sender: sender.addr,
    signer,
    boxes,
    appForeignApps: foreignApps,
    appForeignAssets: assets,
    appAccounts: accounts,
    suggestedParams: { ...sp, fee, flatFee: true },
  });
  const r = await atc.execute(algod, 6);
  return { value: r.methodResults[0].returnValue, txId: r.txIDs.at(-1) };
}

const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const box = (app, prefix, raw) => ({ appIndex: app, name: new Uint8Array([...Buffer.from(prefix), ...raw]) });
const addrBox = (app, prefix, a) => box(app, prefix, algosdk.decodeAddress(a).publicKey);

// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// The box-creating methods (new_agent, accept_feedback, post_job, submit_result,
// fund_job, place_bid, record_job_verdict) now take a LEADING `pay` argument: the
// caller funds the box minimum balance instead of the app account carrying it,
// which closed a permanent-DoS hole where one registration against a drained app
// account bricked the registry. This builds that funding payment — from the same
// account making the call, to the app whose box is created — as a
// TransactionWithSigner, so it is passed as the method's first ABI arg and the
// AtomicTransactionComposer groups it immediately before the app call.
// A single box costs 2500 + 400*(name+value) microALGO (~0.03 ALGO); 200000 is a
// safe over-estimate for one box and 400000 where several may be created.
const mbrPay = async (from, appId, micro) => {
  const sp = await algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: from.addr,
    receiver: algosdk.getApplicationAddress(appId).toString(),
    amount: micro,
    suggestedParams: sp,
  });
  return { txn, signer: algosdk.makeBasicAccountTransactionSigner(from) };
};

console.log("── deploying ──");
const identity = await deploy("IdentityRegistry");
const reputation = await deploy("ReputationRegistry");
const validation = await deploy("ValidationRegistry");

console.log("\n── funding app accounts for box storage ──");
// Just enough MBR for the boxes each test writes. A box costs
// 2500 + 400*(len(name)+len(value)) microALGO, so an agent record is ~0.03.
await fund(identity, 0.35);
await fund(reputation, 0.25);
await fund(validation, 0.85);
console.log("  funded");

console.log("\n── bootstrapping ──");
await call({
  appId: reputation,
  method: M("bootstrap", [{ type: "uint64" }, { type: "uint64" }], "bool"),
  args: [identity, ASSET],
});
await call({
  appId: validation,
  method: M("bootstrap", [{ type: "uint64" }, { type: "uint64" }, { type: "uint64" }, { type: "uint64" }], "bool"),
  // Short enough that the "validator never showed up" path is observable
  // inside one run; production would be days.
  //
  // It has to come from config because chain time is not wall time. LocalNet
  // produces a block only when a transaction arrives, and stamps each one
  // roughly 25 SECONDS ahead of the last — so four rounds of setup advance the
  // chain by a hundred seconds while the script runs for two. A 20s window is
  // shorter than one LocalNet block, which makes every assignment expire the
  // instant it is made and reads exactly like a broken deadline check.
  args: [identity, reputation, ASSET, DISPUTE_WINDOW],
});
// Named after both exist. The reputation registry is deployed first, so it
// cannot name the validation registry at bootstrap — and record_validation
// refuses every caller until this is set.
await call({
  appId: reputation,
  method: M("set_validation_app", [{ type: "uint64" }], "bool"),
  args: [validation],
});
// The app cannot receive the escrow asset until it has opted in, and it needs
// the 0.1 ALGO minimum balance for the holding first.
await fund(validation, 0.2);
await call({
  appId: validation,
  method: M("opt_in_asset", [], "bool"),
  fee: 4000,
  assets: [ASSET],
});
console.log(`  reputation -> identity ${identity}, asset ${ASSET}`);
console.log(`  validation -> identity ${identity}`);

console.log("\n── registering two agents ──");
// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// new_agent creates three boxes (ag_, dm_, ad_), so the caller pre-funds their
// MBR with a leading payment to the IdentityRegistry app account.
const newAgent = M("new_agent", [{ type: "pay" }, { type: "string" }], "uint64");

async function register(acct, domain, nextId) {
  const r = await call({
    appId: identity,
    method: newAgent,
    args: [await mbrPay(acct, identity, 400_000), domain],
    sender: acct,
    boxes: [
      addrBox(identity, "ad_", acct.addr.toString()),
      box(identity, "dm_", Buffer.from(domain)),
      box(identity, "ag_", u64(nextId)),
    ],
  });
  console.log(`  ${domain} -> agent ${r.value}`);
  return Number(r.value);
}

const serverId = await register(deployer, "ripar-agent.vercel.app", 1);
const clientId = await register(other, "client.ripar.io", 2);

/* ── the attacks ──────────────────────────────────────────────────────── */
console.log("\n── attacking the fixed contracts ──");
const results = {};
const attempt = async (label, fn, shouldFail = true) => {
  try {
    await fn();
    results[label] = !shouldFail;
    console.log(`  ${shouldFail ? "FAIL — allowed" : "PASS — allowed"}  ${label}`);
  } catch (e) {
    const msg = String(e?.message ?? "");
    const rejected = /logic eval error|assert/i.test(msg);
    results[label] = shouldFail && rejected;
    console.log(`  ${shouldFail && rejected ? "PASS — rejected" : "FAIL"}  ${label}`);
    if (!shouldFail) console.log("      " + msg.slice(0, 160));
  }
};

// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// accept_feedback now leads with a `pay` funding the sc_ score box; the settling
// axfer follows it.
const acceptFeedback = M(
  "accept_feedback",
  [{ type: "pay" }, { type: "axfer" }, { type: "uint64" }, { type: "uint64" }],
  "uint64"
);
const sp0 = await algod.getTransactionParams().do();

/** A transfer to whoever we like, from whoever we like. */
const transfer = (from, to, amount) =>
  algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: from.addr,
    receiver: to,
    amount,
    assetIndex: ASSET,
    suggestedParams: sp0,
  });

// 1. Pay somewhere else entirely, then claim credit for the server agent.
await attempt("a payment to a third party cannot credit an agent", async () => {
  const t = transfer(other, other.addr.toString(), 1000);
  await call({
    appId: reputation,
    method: acceptFeedback,
    args: [await mbrPay(other, reputation, 200_000), { txn: t, signer: algosdk.makeBasicAccountTransactionSigner(other) }, serverId, clientId],
    sender: other,
    fee: 5000,
    foreignApps: [identity],
    boxes: [box(reputation, "sc_", u64(serverId)), box(identity, "ag_", u64(serverId))],
  });
});

// 2. Pay the right agent, but claim the payment came from someone it did not.
await attempt("a payment from the wrong client is refused", async () => {
  const t = transfer(deployer, deployer.addr.toString(), 1000);
  await call({
    appId: reputation,
    method: acceptFeedback,
    args: [await mbrPay(deployer, reputation, 200_000), { txn: t, signer: algosdk.makeBasicAccountTransactionSigner(deployer) }, serverId, clientId],
    fee: 5000,
    foreignApps: [identity],
    boxes: [box(reputation, "sc_", u64(serverId)), box(identity, "ag_", u64(serverId))],
  });
});

// 3. The real thing: client pays server, credit follows.
await attempt(
  "a real client-to-server payment DOES credit",
  async () => {
    const t = transfer(other, deployer.addr.toString(), 10_000);
    const r = await call({
      appId: reputation,
      method: acceptFeedback,
      args: [await mbrPay(other, reputation, 200_000), { txn: t, signer: algosdk.makeBasicAccountTransactionSigner(other) }, serverId, clientId],
      sender: other,
      fee: 6000,
      foreignApps: [identity],
      boxes: [
        box(reputation, "sc_", u64(serverId)),
        box(identity, "ag_", u64(serverId)),
        box(identity, "ag_", u64(clientId)),
      ],
    });
    console.log("      jobs_paid now:", r.value);
  },
  false
);

/* ── validation authorisation ─────────────────────────────────────────── */
// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// post_job funds the jb_ job box and submit_result funds the result-hash write;
// both now lead with a `pay`. validation_response is unchanged BUT no longer
// inner-calls reputation — the verdict is synced separately by record_job_verdict
// (added below), which funds the sc_ score write to the reputation app.
const postJob = M(
  "post_job",
  [{ type: "pay" }, { type: "byte[]" }, { type: "uint64" }, { type: "uint64" }],
  "uint64"
);
const assignJob = M("assign_job", [{ type: "uint64" }, { type: "uint64" }], "bool");
const submitResult = M("submit_result", [{ type: "pay" }, { type: "uint64" }, { type: "byte[]" }], "bool");
const validationResponse = M("validation_response", [{ type: "uint64" }, { type: "bool" }], "uint64");
const recordJobVerdict = M("record_job_verdict", [{ type: "pay" }, { type: "uint64" }], "bool");

// Sync a decided job's verdict through to the assignee's reputation score. Since
// validation_response stopped inner-calling reputation, this is the step that
// moves Score.validated/disputed. The payment funds the sc_ box on the reputation
// app (>= 37000 microALGO). Grouped: pay-to-reputation-app + the app call on
// ValidationRegistry, which inner-calls identity.agent_address and
// reputation.record_validation.
async function syncVerdict(job, assigneeId, funder = other) {
  return call({
    appId: validation,
    method: recordJobVerdict,
    args: [await mbrPay(funder, reputation, 40_000), job],
    sender: funder,
    fee: 8000,
    foreignApps: [identity, reputation],
    boxes: [
      box(validation, "jb_", u64(job)),
      box(identity, "ag_", u64(assigneeId)),
      box(reputation, "sc_", u64(assigneeId)),
    ],
  });
}

const specHash = new Uint8Array(32).fill(7);
const jobRes = await call({
  appId: validation,
  method: postJob,
  args: [await mbrPay(deployer, validation, 200_000), specHash, 1_000_000, clientId],
  boxes: [box(validation, "jb_", u64(1))],
});
const jobId = Number(jobRes.value);
console.log(`\n  posted job ${jobId} (validator = agent ${clientId})`);

await call({
  appId: validation,
  method: assignJob,
  args: [jobId, serverId],
  boxes: [box(validation, "jb_", u64(jobId))],
});

// 4. Someone who is not the assignee tries to submit.
await attempt("only the assigned agent may submit a result", async () => {
  await call({
    appId: validation,
    method: submitResult,
    args: [await mbrPay(other, validation, 200_000), jobId, new Uint8Array(32).fill(9)],
    sender: other,
    fee: 5000,
    foreignApps: [identity],
    boxes: [box(validation, "jb_", u64(jobId)), box(identity, "ag_", u64(serverId))],
  });
});

// The real assignee submits.
await attempt(
  "the assignee CAN submit",
  async () => {
    await call({
      appId: validation,
      method: submitResult,
      args: [await mbrPay(deployer, validation, 200_000), jobId, new Uint8Array(32).fill(9)],
      fee: 5000,
      foreignApps: [identity],
      boxes: [box(validation, "jb_", u64(jobId)), box(identity, "ag_", u64(serverId))],
    });
  },
  false
);

// 5. The old hole: a stranger marking a job validated.
await attempt("a stranger cannot mark a job validated", async () => {
  await call({
    appId: validation,
    method: validationResponse,
    args: [jobId, true],
    sender: deployer, // the client, but a VALIDATOR was named — so not permitted
    fee: 5000,
    foreignApps: [identity],
    boxes: [box(validation, "jb_", u64(jobId)), box(identity, "ag_", u64(clientId))],
  });
});

// The named validator judges it.
await attempt(
  "the named validator CAN judge",
  async () => {
    const r = await call({
      appId: validation,
      method: validationResponse,
      args: [jobId, true],
      sender: other,
      // NOTE: updated for the audit-fix ABI; not yet re-run against a live
      // network. validation_response now resolves only the caller against
      // identity (one inner call) and NO LONGER inner-calls reputation — a
      // starved reputation app can no longer force a verdict to fail. The score
      // write is a separate, funded record_job_verdict below.
      fee: 5000,
      foreignApps: [identity],
      boxes: [
        box(validation, "jb_", u64(jobId)),
        box(identity, "ag_", u64(clientId)),
      ],
    });
    console.log("      status now:", r.value, "(3 = VALIDATED)");
  },
  false
);
// Sync the decided verdict to the assignee's (serverId) score.
await syncVerdict(jobId, serverId);

/* ── escrow: the one place Ripar takes custody ────────────────────────── */
console.log("\n── escrow ──");

// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// fund_job now leads with a `pay` funding the es_ escrow box; the USDC axfer
// follows it.
const fundJob = M("fund_job", [{ type: "pay" }, { type: "axfer" }, { type: "uint64" }], "uint64");
const releaseEscrow = M("release_escrow", [{ type: "uint64" }], "uint64");
const refundEscrow = M("refund_escrow", [{ type: "uint64" }], "uint64");
const getEscrow = M("get_escrow", [{ type: "uint64" }], "uint64");
const setValidator = M("set_validator", [{ type: "uint64" }, { type: "uint64" }], "bool");

const appAddr = algosdk.getApplicationAddress(validation).toString();
const bal = async (a) => {
  const acc = await algod.accountInformation(a).do();
  const h = (acc.assets ?? []).find((x) => Number(x.assetId ?? x["asset-id"]) === ASSET);
  return Number(h?.amount ?? 0);
};

// A second job, funded, so the money path is exercised end to end.
const spec2 = new Uint8Array(32).fill(11);
const job2 = Number(
  (await call({
    appId: validation,
    method: postJob,
    args: [await mbrPay(deployer, validation, 200_000), spec2, 500_000, clientId],
    boxes: [box(validation, "jb_", u64(2))],
  })).value
);
console.log(`  posted job ${job2}`);

// A stranger cannot fund somebody else's job into escrow.
await attempt("only the client may fund their own job", async () => {
  const sp = await algod.getTransactionParams().do();
  const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: other.addr, receiver: appAddr, amount: 1000, assetIndex: ASSET, suggestedParams: sp,
  });
  await call({
    appId: validation, method: fundJob,
    args: [await mbrPay(other, validation, 200_000), { txn: t, signer: algosdk.makeBasicAccountTransactionSigner(other) }, job2],
    sender: other, fee: 4000, assets: [ASSET],
    boxes: [box(validation, "jb_", u64(job2)), box(validation, "es_", u64(job2))],
  });
});

// The client funds it for real.
const merchantBefore = await bal(deployer.addr.toString());
await attempt("the client CAN fund their job", async () => {
  const sp = await algod.getTransactionParams().do();
  const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: deployer.addr, receiver: appAddr, amount: 500_000, assetIndex: ASSET, suggestedParams: sp,
  });
  const r = await call({
    appId: validation, method: fundJob,
    args: [await mbrPay(deployer, validation, 200_000), { txn: t, signer: algosdk.makeBasicAccountTransactionSigner(deployer) }, job2],
    fee: 4000, assets: [ASSET],
    boxes: [box(validation, "jb_", u64(job2)), box(validation, "es_", u64(job2))],
  });
  console.log("      escrow held:", Number(r.value) / 1e6);
}, false);

const heldOnChain = await bal(appAddr);
console.log("  app account really holds:", heldOnChain / 1e6, "USDC");

// Releasing before the work passed must fail — the status gate, not a balance check.
await attempt("escrow cannot be released before the work passes", async () => {
  await call({
    appId: validation, method: releaseEscrow, args: [job2],
    fee: 5000, foreignApps: [identity], assets: [ASSET],
    accounts: [deployer.addr.toString()],
    boxes: [box(validation, "jb_", u64(job2)), box(validation, "es_", u64(job2)), box(identity, "ag_", u64(serverId))],
  });
});

// Drive job 2 to VALIDATED so release becomes legal.
await call({ appId: validation, method: assignJob, args: [job2, serverId], boxes: [box(validation, "jb_", u64(job2))] });
await call({
  appId: validation, method: submitResult, args: [await mbrPay(deployer, validation, 200_000), job2, new Uint8Array(32).fill(12)],
  fee: 5000, foreignApps: [identity],
  boxes: [box(validation, "jb_", u64(job2)), box(identity, "ag_", u64(serverId))],
});
// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// validation_response no longer inner-calls reputation; the score write is the
// separate record_job_verdict that follows.
await call({
  appId: validation, method: validationResponse, args: [job2, true],
  sender: other, fee: 5000, foreignApps: [identity],
  boxes: [
    box(validation, "jb_", u64(job2)),
    box(identity, "ag_", u64(clientId)),
  ],
});
await syncVerdict(job2, serverId);

// A stranger cannot release inside the dispute window.
await attempt("a stranger cannot release inside the dispute window", async () => {
  await call({
    appId: validation, method: releaseEscrow, args: [job2],
    sender: other, fee: 5000, foreignApps: [identity], assets: [ASSET],
    accounts: [deployer.addr.toString()],
    boxes: [box(validation, "jb_", u64(job2)), box(validation, "es_", u64(job2)), box(identity, "ag_", u64(serverId))],
  });
});

// The client can, immediately. The assignee is agent 1, whose address is the
// deployer — so the money comes back to where it started, which is fine: what
// is being proved is that the CONTRACT moved it, not who ended up with it.
const assigneeBefore = await bal(deployer.addr.toString());
await attempt("the client CAN release once the work passed", async () => {
  const r = await call({
    appId: validation, method: releaseEscrow, args: [job2],
    fee: 5000, foreignApps: [identity], assets: [ASSET],
    accounts: [deployer.addr.toString()],
    boxes: [box(validation, "jb_", u64(job2)), box(validation, "es_", u64(job2)), box(identity, "ag_", u64(serverId))],
  });
  console.log("      released:", Number(r.value) / 1e6, "USDC");
}, false);

const assigneeAfter = await bal(deployer.addr.toString());
const appAfter = await bal(appAddr);
console.log("  assignee gained:", (assigneeAfter - assigneeBefore) / 1e6);
console.log("  app account now :", appAfter / 1e6);

// And it cannot be released twice: the box is cleared before the transfer.
await attempt("escrow cannot be released twice", async () => {
  await call({
    appId: validation, method: releaseEscrow, args: [job2],
    fee: 5000, foreignApps: [identity], assets: [ASSET],
    accounts: [deployer.addr.toString()],
    boxes: [box(validation, "jb_", u64(job2)), box(validation, "es_", u64(job2)), box(identity, "ag_", u64(serverId))],
  });
});

// set_validator is client-only and open-only.
await attempt("a stranger cannot rename the validator", async () => {
  await call({
    appId: validation, method: setValidator, args: [job2, serverId],
    sender: other, boxes: [box(validation, "jb_", u64(job2))],
  });
});

results["the escrow really moved on chain"] =
  heldOnChain >= 500_000 && assigneeAfter - assigneeBefore === 500_000 && appAfter === 0;
console.log(
  `  ${results["the escrow really moved on chain"] ? "PASS" : "FAIL"}  the escrow really moved on chain`
);

/* ── bidding, milestones, expiry, rotation ─────────────────────────────── */
console.log("\n── bidding ──");

// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// place_bid now leads with a `pay` funding the bd_ bid box.
const placeBid = M("place_bid", [{ type: "pay" }, { type: "uint64" }, { type: "uint64" }, { type: "uint64" }, { type: "byte[]" }], "bool");
const acceptBid = M("accept_bid", [{ type: "uint64" }, { type: "uint64" }], "bool");
const withdrawBid = M("withdraw_bid", [{ type: "uint64" }, { type: "uint64" }], "bool");
const releasePartial = M("release_partial", [{ type: "uint64" }, { type: "uint64" }], "uint64");
const expireJob = M("expire_job", [{ type: "uint64" }], "bool");
const rotateAddress = M("rotate_address", [{ type: "uint64" }, { type: "address" }], "bool");

const bidKey = (job, bidder) => new Uint8Array([...Buffer.from("bd_"), ...u64(job), ...u64(bidder)]);
const pitch = new Uint8Array(32).fill(21);

// A fresh OPEN job to bid on.
const job3 = Number(
  (await call({
    appId: validation, method: postJob, args: [await mbrPay(deployer, validation, 200_000), new Uint8Array(32).fill(31), 1_000_000, clientId],
    boxes: [box(validation, "jb_", u64(3))],
  })).value
);
console.log(`  posted job ${job3}`);

// The client cannot bid on their own job.
await attempt("the client cannot bid on their own job", async () => {
  await call({
    appId: validation, method: placeBid, args: [await mbrPay(deployer, validation, 200_000), job3, serverId, 400_000, pitch],
    fee: 5000, foreignApps: [identity],
    boxes: [box(validation, "jb_", u64(job3)), { appIndex: validation, name: bidKey(job3, serverId) }, box(identity, "ag_", u64(serverId))],
  });
});

// An agent cannot bid on behalf of another.
await attempt("an agent cannot place a bid for somebody else", async () => {
  await call({
    appId: validation, method: placeBid, args: [await mbrPay(other, validation, 200_000), job3, serverId, 400_000, pitch],
    sender: other, fee: 5000, foreignApps: [identity],
    boxes: [box(validation, "jb_", u64(job3)), { appIndex: validation, name: bidKey(job3, serverId) }, box(identity, "ag_", u64(serverId))],
  });
});

// Agent 2 (the `other` account) bids for real.
await attempt("an agent CAN bid on an open job", async () => {
  await call({
    appId: validation, method: placeBid, args: [await mbrPay(other, validation, 200_000), job3, clientId, 400_000, pitch],
    sender: other, fee: 5000, foreignApps: [identity],
    boxes: [box(validation, "jb_", u64(job3)), { appIndex: validation, name: bidKey(job3, clientId) }, box(identity, "ag_", u64(clientId))],
  });
}, false);

// Only the client accepts.
await attempt("a stranger cannot accept a bid", async () => {
  await call({
    appId: validation, method: acceptBid, args: [job3, clientId],
    sender: other,
    boxes: [box(validation, "jb_", u64(job3)), { appIndex: validation, name: bidKey(job3, clientId) }],
  });
});

await attempt("the client CAN accept a bid, and the budget becomes the bid", async () => {
  await call({
    appId: validation, method: acceptBid, args: [job3, clientId],
    boxes: [box(validation, "jb_", u64(job3)), { appIndex: validation, name: bidKey(job3, clientId) }],
  });
  const raw = Buffer.from(
    (await algod.getApplicationBoxByName(validation, new Uint8Array([...Buffer.from("jb_"), ...u64(job3)])).do()).value
  );
  const budget = Number(raw.readBigUInt64BE(56));
  console.log("      budget is now:", budget / 1e6, "(bid was 0.4)");
  results["accepting a bid rewrites the budget to the bid"] = budget === 400_000;
}, false);
console.log(
  `  ${results["accepting a bid rewrites the budget to the bid"] ? "PASS" : "FAIL"}  accepting a bid rewrites the budget to the bid`
);

// Bids close once assigned.
await attempt("bids close once the job is assigned", async () => {
  await call({
    appId: validation, method: placeBid, args: [await mbrPay(other, validation, 200_000), job3, clientId, 300_000, pitch],
    sender: other, fee: 5000, foreignApps: [identity],
    boxes: [box(validation, "jb_", u64(job3)), { appIndex: validation, name: bidKey(job3, clientId) }, box(identity, "ag_", u64(clientId))],
  });
});

/* ── milestones ───────────────────────────────────────────────────────── */
console.log("\n── milestones ──");

// Job 3 is assigned to agent 2 (other). Fund it, drive it to VALIDATED, then
// release half.
{
  const sp = await algod.getTransactionParams().do();
  const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: deployer.addr, receiver: appAddr, amount: 400_000, assetIndex: ASSET, suggestedParams: sp,
  });
  await call({
    appId: validation, method: fundJob,
    args: [await mbrPay(deployer, validation, 200_000), { txn: t, signer: algosdk.makeBasicAccountTransactionSigner(deployer) }, job3],
    fee: 4000, assets: [ASSET],
    boxes: [box(validation, "jb_", u64(job3)), box(validation, "es_", u64(job3))],
  });
}
await call({
  appId: validation, method: submitResult, args: [await mbrPay(other, validation, 200_000), job3, new Uint8Array(32).fill(41)],
  sender: other, fee: 5000, foreignApps: [identity],
  boxes: [box(validation, "jb_", u64(job3)), box(identity, "ag_", u64(clientId))],
});
// NOTE: updated for the audit-fix ABI; not yet re-run against a live network.
// validation_response no longer inner-calls reputation; record_job_verdict below
// writes the score. Job 3's assignee is clientId (agent 2), so the verdict lands
// on that agent's score box.
await call({
  appId: validation, method: validationResponse, args: [job3, true],
  sender: other, fee: 5000, foreignApps: [identity],
  boxes: [box(validation, "jb_", u64(job3)), box(identity, "ag_", u64(clientId))],
});
await syncVerdict(job3, clientId);

await attempt("cannot release more than is held", async () => {
  await call({
    appId: validation, method: releasePartial, args: [job3, 999_000_000],
    fee: 5000, foreignApps: [identity], assets: [ASSET], accounts: [other.addr.toString()],
    boxes: [box(validation, "jb_", u64(job3)), box(validation, "es_", u64(job3)), box(identity, "ag_", u64(clientId))],
  });
});

await attempt("the client CAN release a milestone, and the rest stays held", async () => {
  const r = await call({
    appId: validation, method: releasePartial, args: [job3, 100_000],
    fee: 5000, foreignApps: [identity], assets: [ASSET], accounts: [other.addr.toString()],
    boxes: [box(validation, "jb_", u64(job3)), box(validation, "es_", u64(job3)), box(identity, "ag_", u64(clientId))],
  });
  console.log("      remaining held:", Number(r.value) / 1e6);
  results["a partial release leaves the rest escrowed"] = Number(r.value) === 300_000;
}, false);
console.log(
  `  ${results["a partial release leaves the rest escrowed"] ? "PASS" : "FAIL"}  a partial release leaves the rest escrowed`
);

/* ── expiry ───────────────────────────────────────────────────────────── */
console.log("\n── expiry ──");
const job4 = Number(
  (await call({
    appId: validation, method: postJob, args: [await mbrPay(deployer, validation, 200_000), new Uint8Array(32).fill(51), 100_000, 0],
    boxes: [box(validation, "jb_", u64(4))],
  })).value
);
await call({ appId: validation, method: assignJob, args: [job4, serverId], boxes: [box(validation, "jb_", u64(job4))] });

await attempt("an assigned job cannot expire before its deadline", async () => {
  await call({ appId: validation, method: expireJob, args: [job4], boxes: [box(validation, "jb_", u64(job4))] });
});

/**
 * Advance the CHAIN clock, not the wall clock.
 *
 * `expire_job` compares against `Global.latest_timestamp`, which only moves
 * when a block is produced. A public network produces one every few seconds
 * whether or not anyone is looking, so sleeping was enough there. LocalNet
 * produces a block only when a transaction arrives — idle for eight real
 * seconds, its round and timestamp do not move at all — so a plain sleep left
 * the window permanently open and the two expiry tests failing against a
 * contract that is correct.
 *
 * Self-payments of zero are the cheapest thing that forces a round.
 */
async function advanceChain(seconds) {
  const stamp = async () => {
    const status = await algod.status().do();
    const blk = await algod.block(Number(status.lastRound)).do();
    return Number(blk.block?.ts ?? blk.block?.header?.timestamp ?? 0);
  };
  const start = await stamp();
  process.stdout.write(`  advancing the chain past the ${seconds}s dispute window`);
  while ((await stamp()) - start < seconds + 2) {
    const sp = await algod.getTransactionParams().do();
    const nudge = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: deployer.addr,
      receiver: deployer.addr,
      amount: 0,
      suggestedParams: sp,
    });
    const { txid } = await algod.sendRawTransaction(nudge.signTxn(deployer.sk)).do();
    await algosdk.waitForConfirmation(algod, txid, 6);
    process.stdout.write(".");
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.log(` chain moved ${(await stamp()) - start}s`);
}

await advanceChain(DISPUTE_WINDOW);

await attempt("ANYONE may expire an abandoned assignment", async () => {
  await call({
    appId: validation, method: expireJob, args: [job4],
    sender: other, boxes: [box(validation, "jb_", u64(job4))],
  });
}, false);

/* ── key rotation ─────────────────────────────────────────────────────── */
console.log("\n── key rotation ──");
const fresh = algosdk.generateAccount();

await attempt("a stranger cannot rotate an agent's address", async () => {
  await call({
    appId: identity, method: rotateAddress, args: [serverId, fresh.addr.toString()],
    sender: other,
    boxes: [box(identity, "ag_", u64(serverId)), addrBox(identity, "ad_", deployer.addr.toString()), addrBox(identity, "ad_", fresh.addr.toString())],
  });
});

await attempt("rotating to an address that already controls an agent is refused", async () => {
  await call({
    appId: identity, method: rotateAddress, args: [serverId, other.addr.toString()],
    boxes: [box(identity, "ag_", u64(serverId)), addrBox(identity, "ad_", deployer.addr.toString()), addrBox(identity, "ad_", other.addr.toString())],
  });
});

await attempt("the owner CAN rotate, and the OLD address stops resolving", async () => {
  await call({
    appId: identity, method: rotateAddress, args: [serverId, fresh.addr.toString()],
    boxes: [box(identity, "ag_", u64(serverId)), addrBox(identity, "ad_", deployer.addr.toString()), addrBox(identity, "ad_", fresh.addr.toString())],
  });
  const old = await algod
    .getApplicationBoxByName(identity, addrBox(identity, "ad_", deployer.addr.toString()).name).do()
    .then(() => true).catch(() => false);
  const now = await algod
    .getApplicationBoxByName(identity, addrBox(identity, "ad_", fresh.addr.toString()).name).do()
    .then((b) => Number(Buffer.from(b.value).readBigUInt64BE(0))).catch(() => 0);
  console.log("      old address still resolves:", old, "| new address resolves to:", now);
  // The old index MUST be gone, or a caller checking "does the card's payTo
  // match the registry" still gets a match on the compromised key.
  results["rotation removes the old reverse index"] = !old && now === serverId;
}, false);
console.log(
  `  ${results["rotation removes the old reverse index"] ? "PASS" : "FAIL"}  rotation removes the old reverse index`
);

// Put it back, so the rest of the system keeps working.
{
  const sp = await algod.getTransactionParams().do();
  const fund = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployer.addr, receiver: fresh.addr, amount: 300_000, suggestedParams: sp,
  });
  const { txid } = await algod.sendRawTransaction(fund.signTxn(deployer.sk)).do();
  await algosdk.waitForConfirmation(algod, txid, 6);
  await call({
    appId: identity, method: rotateAddress, args: [serverId, deployer.addr.toString()],
    sender: fresh,
    boxes: [box(identity, "ag_", u64(serverId)), addrBox(identity, "ad_", fresh.addr.toString()), addrBox(identity, "ad_", deployer.addr.toString())],
  });
  console.log("  rotated back to the deployer");
}

/* ── the verdict has to reach the score ────────────────────────────────── */
console.log("\n── does a verdict reach the score? ──");
const scoreBox = await algod
  .getApplicationBoxByName(reputation, new Uint8Array([...Buffer.from("sc_"), ...u64(serverId)]))
  .do()
  .then((b) => Buffer.from(b.value))
  .catch(() => null);

if (scoreBox) {
  const validated = Number(scoreBox.readBigUInt64BE(24));
  const disputed = Number(scoreBox.readBigUInt64BE(32));
  console.log(`  score: validated ${validated}, disputed ${disputed}`);
  // Two jobs were judged and passed in this run. Before record_validation was
  // wired through, both counters sat at 0 while the jobs read VALIDATED — and
  // a reader comparing the two had no way to tell which number was wrong.
  results["a passing verdict reaches the agent's score"] = validated === 2 && disputed === 0;
  console.log(
    `  ${results["a passing verdict reaches the agent's score"] ? "PASS" : "FAIL"}  a passing verdict reaches the agent's score`
  );
} else {
  results["a passing verdict reaches the agent's score"] = false;
  console.log("  FAIL  no score box at all");
}

// And nobody but the ValidationRegistry may write one.
await attempt("an address cannot record a verdict directly", async () => {
  await call({
    appId: reputation,
    // NOTE: updated for the audit-fix ABI; not yet re-run against a live
    // network. record_validation gained a leading job_id and is now callable
    // only by ValidationRegistry.record_job_verdict — a direct address call is
    // still refused, which is what this negative test proves.
    method: M("record_validation", [{ type: "uint64" }, { type: "uint64" }, { type: "bool" }], "bool"),
    args: [jobId, serverId, true],
    sender: other,
    boxes: [box(reputation, "sc_", u64(serverId))],
  });
});

console.log("\n── verdict ──");
const ok = Object.values(results).every(Boolean);
for (const [k, v] of Object.entries(results)) console.log(`  ${v ? "PASS" : "FAIL"}  ${k}`);

const out = {
  network: "testnet",
  deployer: deployer.addr.toString(),
  registries: { identity, reputation, validation },
  agents: { server: serverId, client: clientId },
  asset: ASSET,
};
fs.writeFileSync("/tmp/registries-v2.json", JSON.stringify(out, null, 2));

// Fold the ids back into the e2e config. Downstream scripts then need ONE file
// to know both who the accounts are and which apps they are talking to — the
// alternative is a DEPLOYED.json that only ever describes one network, which is
// how a LocalNet run ends up reading TestNet app ids.
const cfgPath = configPath("testnet-e2e.json");
const merged = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
merged.registries = { identity, reputation, validation };
merged.agents = { server: serverId, client: clientId };
fs.writeFileSync(cfgPath, JSON.stringify(merged, null, 2) + "\n", { mode: 0o600 });
console.log(`\nregistry ids written to ${cfgPath}`);
console.log("\n" + JSON.stringify(out, null, 2));
process.exit(ok ? 0 : 1);
