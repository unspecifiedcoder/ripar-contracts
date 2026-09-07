/**
 * Deploy the three registries to a real network — and NOTHING else.
 *
 * `deploy-v2.mjs` is a deploy-AND-ATTACK script: only its first ~181 lines
 * deploy, and the ~650 that follow register fixture agents on test domains,
 * push real USDC through escrow, and at line 718 generate an in-memory account,
 * fund it 0.3 ALGO and never sweep it — the key is never written to disk. On a
 * network where ALGO costs money that is 0.3 ALGO destroyed per run plus
 * permanent junk records in a production registry.
 *
 * This file is that deploy prefix, taken verbatim so the bytecode path stays
 * byte-identical to what has been proven on LocalNet and TestNet, with three
 * things parameterised:
 *
 *   RIPAR_CONFIG    which key file to read      (default testnet-e2e.json)
 *   ALGOD_URL       which node to deploy to     (NO default — must be explicit)
 *   RIPAR_NETWORK   the label written to output (default from the config)
 *
 * ALGOD_URL deliberately has no fallback. deploy-v2.mjs defaults it to
 * testnet-api.algonode.cloud, so forgetting the variable silently deploys to
 * the wrong chain; here it refuses to start.
 *
 * Everything this writes is one-shot. `bootstrap` asserts its fields are zero,
 * so a wrong asset id or dispute window cannot be corrected — only redeployed,
 * with new app ids, and every repo repointed.
 */
import algosdk from "algosdk";
import fs from "node:fs";
import { configPath } from "./config-path.mjs";

const CONFIG_NAME = process.env.RIPAR_CONFIG ?? "testnet-e2e.json";
const cfg = JSON.parse(fs.readFileSync(configPath(CONFIG_NAME), "utf8"));
const NETWORK = process.env.RIPAR_NETWORK ?? cfg.network ?? "testnet";

if (!process.env.ALGOD_URL) {
  console.error(
    "ALGOD_URL is required. This script will not guess a network: deploying\n" +
    "the wrong chain mints permanent app ids and locks ALGO in minimum balance.\n" +
    "  LocalNet  ALGOD_URL=http://localhost:4001 ALGOD_TOKEN=aaaa...(64 a's)\n" +
    "  TestNet   ALGOD_URL=https://testnet-api.algonode.cloud\n" +
    "  MainNet   ALGOD_URL=https://mainnet-api.algonode.cloud"
  );
  process.exit(1);
}
const algod = new algosdk.Algodv2(
  process.env.ALGOD_TOKEN ?? "",
  process.env.ALGOD_URL,
  process.env.ALGOD_PORT ?? ""
);

const deployer = algosdk.mnemonicToSecretKey(cfg.merchant.mnemonic);
const other = cfg.payer?.mnemonic
  ? algosdk.mnemonicToSecretKey(cfg.payer.mnemonic)
  : null; // only the attack suite needed a second account; deploying does not
const ASSET = cfg.assetId;

// The dispute window is one-shot: `bootstrap` takes it permanently. A 20-second
// production window lets ANYONE call expire_verdict then release_escrow ~40s
// after a result is submitted, draining the escrow before the client or a real
// validator can look at the work. So on a public chain it is not allowed to
// default and it is not allowed to be short — refuse to start, the same way this
// script refuses to start without an explicit ALGOD_URL. LocalNet is exempt: its
// blocks are ~25s apart, so the attack suite must use a window of seconds.
const isLocalNet =
  /localhost|127\.0\.0\.1|:4001\b/.test(process.env.ALGOD_URL) ||
  /local/i.test(NETWORK);
if (!isLocalNet) {
  if (cfg.disputeWindowSecs == null) {
    throw new Error(
      `disputeWindowSecs is missing from ${CONFIG_NAME}. On ${NETWORK} it must be set ` +
      `explicitly (MainNet uses 259200 = 72h); a defaulted 20s window lets anyone drain ` +
      `escrow ~40s after a result is submitted.`
    );
  }
  if (Number(cfg.disputeWindowSecs) < 3600) {
    throw new Error(
      `disputeWindowSecs is ${cfg.disputeWindowSecs}s on ${NETWORK}, below the 3600s (1h) ` +
      `floor. bootstrap takes it permanently, so a short window cannot be corrected — only ` +
      `redeployed. MainNet is configured for 259200 (72h).`
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

/* ── write the result ──────────────────────────────────────────────────── */

const out = {
  network: NETWORK,
  deployer: deployer.addr.toString(),
  deployedAt: new Date().toISOString(),
  registries: {
    identity: { appId: identity },
    reputation: { appId: reputation, bootstrappedTo: { identityApp: identity, asset: ASSET } },
    validation: {
      appId: validation,
      bootstrappedTo: {
        identityApp: identity,
        reputationApp: reputation,
        escrowAsset: ASSET,
        disputeWindowSecs: DISPUTE_WINDOW,
      },
    },
  },
};

const outPath = `/tmp/ripar-deploy-${NETWORK}.json`;
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));

// Persist the ids back into the config so the follow-up scripts
// (fund-app-accounts, optin-usdc) pick them up without a second edit.
cfg.registries = { identity, reputation, validation };
fs.writeFileSync(configPath(CONFIG_NAME), JSON.stringify(cfg, null, 2));

console.log(`\n── deployed on ${NETWORK} ──`);
console.log(`  identity    ${identity}`);
console.log(`  reputation  ${reputation}`);
console.log(`  validation  ${validation}`);
console.log(`  asset       ${ASSET}`);
console.log(`  window      ${DISPUTE_WINDOW}s`);
console.log(`\n  written to ${outPath} and ${configPath(CONFIG_NAME)}`);
console.log("\n  These app ids are permanent. Every bootstrap field above is one-shot.");
