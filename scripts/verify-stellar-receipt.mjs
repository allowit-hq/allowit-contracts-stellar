#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { parseArgs, promisify } from "node:util";

const run = promisify(execFile);
const rpc = "https://soroban-testnet.stellar.org";
const horizon = "https://horizon-testnet.stellar.org";
// The native Stellar Asset Contract on Stellar Testnet.
const nativeAssetContract = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const address = /^[GC][A-Z2-7]{55}$/;
const hashPattern = /^[a-f0-9]{64}$/;
const argumentNames = ["request-id", "hash", "source", "recipient", "amount", "status-file", "journal-file"];
const testnetId = createHash("sha256").update("Test SDF Network ; September 2015").digest("hex");

function requireMatch(condition, message) {
  if (!condition) throw new Error(message);
}

function stroops(amount) {
  if (typeof amount !== "string" || !/^(0|[1-9][0-9]*)(\.[0-9]{1,7})?$/.test(amount)) return null;
  const [whole, decimal = ""] = amount.split(".");
  return BigInt(whole) * 10_000_000n + BigInt(decimal.padEnd(7, "0"));
}

async function getJson(url, args = []) {
  try {
    const { stdout } = await run("curl", ["--disable", "--silent", "--show-error", "--fail",
      "--connect-timeout", "5", "--max-time", "25", ...args, url], { maxBuffer: 8 * 1024 * 1024 });
    return JSON.parse(stdout);
  } catch {
    throw new Error(`No valid public receipt from ${new URL(url).hostname}`);
  }
}

function horizonRows(reply) {
  const rows = reply?._embedded?.records;
  requireMatch(Array.isArray(rows) && rows.length < 200, "Horizon returned incomplete receipt records");
  return rows;
}

function statusFromDocument(document) {
  if (document?.operation) {
    const { id, status, transactionHash } = document.operation;
    return { requestId: id, status, transactionHash };
  }
  const { requestId, status, transactionHash } = document ?? {};
  return { requestId, status, transactionHash };
}

function hexBytes(value) {
  if (!Array.isArray(value) || value.length !== 32 ||
    !value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) return null;
  return Buffer.from(value).toString("hex");
}

async function strkey(account) {
  const kind = { Wallet: "public_key_ed25519", Contract: "contract" }[account?.kind];
  const hex = hexBytes(account?.address);
  requireMatch(account?.chain === "Stellar" && kind && hex, "Invalid original Stellar payment party");
  const { stdout } = await run("stellar", ["strkey", "encode", JSON.stringify({ [kind]: hex })],
    { timeout: 10_000, maxBuffer: 1024 * 1024 });
  const key = stdout.trim();
  requireMatch(address.test(key), "Could not encode original Stellar payment party");
  return key;
}

async function verifyOriginalRequest(journalFile, expected) {
  const journalBytes = journalFile === "-" ? readFileSync(0) : await readFile(journalFile);
  const record = JSON.parse(journalBytes);
  const { request, config, policyId, prepared, backendOrigin } = record;
  requireMatch(typeof policyId === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(policyId)
    && record.requestId === expected.requestId && config?.network === "stellar:testnet"
    && config.assetSymbol === "XLM" && config.assetIssuer === null && config.asset === nativeAssetContract
    && hexBytes(prepared?.transactionHash) === expected.hash
    && (!expected.origin || backendOrigin === expected.origin),
    "The retained journal does not bind this original Stellar Testnet XLM request and transaction");
  const nonce = createHash("sha256")
    .update("allowit-workflow-operation-v1\0").update(policyId).update("\0").update(record.requestId).digest("hex");
  requireMatch(hexBytes(request?.operation?.nonce) === nonce
    && JSON.stringify(prepared.request) === JSON.stringify(request),
    "The retained transaction does not bind the exact original request");
  const instructions = request.input?.Instructions;
  const payment = instructions?.[0]?.StellarNativeTransfer;
  const effects = request.effect_bounds;
  const bound = effects?.[0];
  const asset = bound?.asset?.Native;
  requireMatch(instructions?.length === 1 && payment && effects?.length === 1
    && asset?.chain === "Stellar" && hexBytes(asset.network) === testnetId
    && Number.isSafeInteger(payment.stroops) && BigInt(payment.stroops) === expected.value,
    "The original request does not specify this exact native XLM payment amount");
  const maxDebit = hexBytes(bound.max_debit);
  const minCredit = hexBytes(bound.min_credit);
  requireMatch(maxDebit && minCredit && BigInt(`0x${maxDebit}`) === expected.value
    && BigInt(`0x${minCredit}`) === expected.value,
    "The retained effect bounds differ from the original XLM payment amount");
  const [source, recipient] = await Promise.all([strkey(payment.source), strkey(payment.destination)]);
  requireMatch(source === expected.source && recipient === expected.recipient && source === config.wallet,
    "The transfer parties differ from the original request and wallet");
  return { policyId, journalSha256: createHash("sha256").update(journalBytes).digest("hex") };
}

async function decodeContractEvent(encoded) {
  const { stdout } = await run("stellar", ["xdr", "decode", "--type", "ContractEvent", encoded],
    { timeout: 10_000, maxBuffer: 1024 * 1024 });
  return JSON.parse(stdout);
}

function nativeAmount(row, amount) {
  return row.asset_type === "native" && stroops(row.amount) === amount;
}

function transferEffect(row, direction, identity, amount) {
  const isContract = identity.startsWith("C");
  return row.type === `${isContract ? "contract" : "account"}_${direction}`
    && (isContract ? row.contract : row.account) === identity && nativeAmount(row, amount);
}

async function verifySorobanTransfer(result, operations, effects, source, recipient, amount) {
  const encoded = result.events?.contractEventsXdr?.flat(1);
  requireMatch(Array.isArray(encoded) && encoded.length > 0 && encoded.length < 200
    && encoded.every(item => typeof item === "string"), "Soroban receipt has no complete contract event list");
  const events = await Promise.all(encoded.map(decodeContractEvent));
  const transfersForParties = events.filter(event => {
    const { topics } = event.body?.v0 ?? {};
    return (event.type ?? event.type_) === "contract" && event.contract_id === nativeAssetContract
      && topics?.[0]?.symbol === "transfer"
      && (topics[1]?.address === source || topics[2]?.address === recipient);
  });
  const { topics, data } = transfersForParties[0]?.body?.v0 ?? {};
  requireMatch(transfersForParties.length === 1 && topics?.length === 4
    && topics[1]?.address === source && topics[2]?.address === recipient
    && topics[3]?.string === "native" && data?.i128 === amount.toString(),
  "Soroban did not report exactly one matching native transfer event");

  const transfers = operations.filter(operation => {
    if (operation.type !== "invoke_host_function") return false;
    const link = operation._links?.self?.href;
    if (!link) return false;
    const scoped = effects.filter(effect => effect._links?.operation?.href === link);
    return scoped.filter(row => transferEffect(row, "debited", source, amount)).length === 1
      && scoped.filter(row => transferEffect(row, "credited", recipient, amount)).length === 1;
  });
  requireMatch(transfers.length === 1, "Horizon did not report one matching debit and credit in the same operation");
}

async function verify() {
  const { values: args } = parseArgs({
    options: Object.fromEntries([...argumentNames, "origin"].map(name => [name, { type: "string" }])),
  });
  const { "request-id": requestId, "status-file": statusFile, hash, source, recipient, amount } = args;
  requireMatch(argumentNames.every(name => args[name]), `Required arguments: ${argumentNames.map(name => `--${name}`).join(" ")}`);
  const value = stroops(amount);
  requireMatch(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(requestId) && hashPattern.test(hash)
    && address.test(source) && address.test(recipient) && source !== recipient
    && value !== null && value > 0n, "Invalid request, hash, transfer parties, or XLM amount");

  const status = statusFromDocument(JSON.parse(await readFile(statusFile, "utf8")));
  requireMatch(status.requestId === requestId && status.transactionHash === hash
    && status.status === "confirmed", "The original application request has no matching confirmed status");
  // Standalone verification proves the on-chain receipt. The recorder obtains the CLI status.
  const journal = await verifyOriginalRequest(args["journal-file"],
    { requestId, hash, source, recipient, value, origin: args.origin });

  const transactionUrl = `${horizon}/transactions/${hash}`;
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getTransaction", params: { hash } });
  const [response, receipt, operationPage] = await Promise.all([
    getJson(rpc, ["--header", "Content-Type: application/json", "--data-binary", body]),
    getJson(transactionUrl),
    getJson(`${transactionUrl}/operations?limit=200`),
  ]);
  const result = response.result;
  requireMatch(result?.status !== "NOT_FOUND", "Soroban RPC has no retained receipt for this transaction");
  requireMatch(response.id === 1 && result?.status === "SUCCESS" && result.txHash === hash
    && Number.isSafeInteger(result.ledger) && result.ledger > 0, "Soroban has no matching successful transaction");
  requireMatch(receipt.hash === hash && receipt.successful === true && receipt.ledger === result.ledger,
    "Horizon transaction differs from the Soroban receipt");
  const operations = horizonRows(operationPage);
  requireMatch(operations.length === 1 && operations[0].transaction_hash === hash
    && operations[0].transaction_successful === true, "Expected one operation in the confirmed transaction");

  if (source.startsWith("C") || recipient.startsWith("C") || operations.some(op => op.type === "invoke_host_function")) {
    const effects = horizonRows(await getJson(`${transactionUrl}/effects?limit=200`));
    await verifySorobanTransfer(result, operations, effects, source, recipient, value);
  } else {
    const payments = operations.filter(row => row.type === "payment" && row.asset_type === "native"
      && (row.from === source || row.to === recipient));
    requireMatch(payments.length === 1 && payments[0].from === source && payments[0].to === recipient
      && nativeAmount(payments[0], value), "Horizon did not report exactly one matching native payment");
  }

  console.log(JSON.stringify({ requestId, transactionHash: hash, ledger: result.ledger,
    source, recipient, amount, asset: "XLM", network: "stellar:testnet", ...journal, verified: true }));
}

verify().catch(error => {
  console.error(`Stellar receipt verification failed: ${error.message}`);
  process.exitCode = 1;
});
