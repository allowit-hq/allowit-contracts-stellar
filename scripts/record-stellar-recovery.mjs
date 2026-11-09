#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const rpc = "https://soroban-testnet.stellar.org";
const receiptArguments = ["request-id", "hash", "source", "recipient", "amount", "journal-file"];
const required = ["origin", "config-dir", "output-dir", ...receiptArguments];
const usage = `node scripts/record-stellar-recovery.mjs ${required.map(name => `--${name} VALUE`).join(" ")} [--allowit PATH]`;
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;

async function record() {
  const { values: args } = parseArgs({
    options: {
      ...Object.fromEntries([...required, "allowit"].map(name => [name, { type: "string" }])),
      help: { type: "boolean" },
    },
  });
  if (args.help) {
    console.log(usage);
    console.log("Read the original request and verify its exact XLM receipt. Use a new output directory for each capture.");
    return;
  }
  if (!required.every(name => args[name])) throw new Error(usage);
  const { origin, "config-dir": configDir, "output-dir": outputDir, "request-id": requestId } = args;
  if (!/^https:\/\/(staging\.allowit\.ai|allowit-backend-7b19f2-[a-z0-9]+-agentools-projects\.vercel\.app)$/.test(origin)) {
    throw new Error("Use the original public staging origin or its Engine Preview");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(requestId)) throw new Error("Invalid request ID");
  const journal = await realpath(args["journal-file"]);
  const journalBytes = await readFile(journal);
  const { policyId, requestId: retainedId, backendOrigin, config } = JSON.parse(journalBytes);
  const nonce = createHash("sha256").update("allowit-workflow-operation-v1\0")
    .update(policyId ?? "").update("\0").update(requestId).digest("hex");
  const fileId = createHash("sha256").update(nonce).digest("hex");
  const expectedJournal = join(await realpath(configDir), "stellar-journal", `request-${fileId}.json`);
  if (journal !== expectedJournal || resolve(args["journal-file"]) !== journal
    || retainedId !== requestId || config?.wallet !== args.source || backendOrigin !== origin) {
    throw new Error("Use this config directory's original request journal, wallet, and backend");
  }
  await mkdir(outputDir, { mode: 0o700 });

  const cli = args.allowit ?? "allowit";
  const statusArgs = [
    "--rail", "stellar:testnet", "--rpc-url", rpc, "--config-dir", configDir, "--wallet", args.source,
    "--json", "status", requestId, "--wait", "0s",
  ];
  console.log(`AllowIt CLI | Stellar Testnet | ${origin}`);
  console.log(`$ env -u ALLOWIT_WALLET ALLOWIT_URL=${quote(origin)} NO_COLOR=1 ${[cli, ...statusArgs].map(quote).join(" ")}`);
  const env = { ...process.env, ALLOWIT_URL: origin, NO_COLOR: "1" };
  delete env.ALLOWIT_WALLET;
  const lookup = spawnSync(cli, statusArgs, {
    encoding: "utf8", timeout: 60_000, maxBuffer: 1024 * 1024,
    env,
  });
  if (lookup.error) throw new Error("The CLI could not read the original request status");

  let status;
  try {
    const { requestId: foundId, status: outcome, transactionHash } = JSON.parse(lookup.stdout);
    if (foundId === requestId && /^[a-zA-Z]+$/.test(outcome) && /^[a-f0-9]{64}$/.test(transactionHash)) {
      status = { requestId: foundId, status: outcome, transactionHash };
    }
  } catch {
    // The CLI may return an error on stderr without a request status.
  }
  if (!status) throw new Error(`The CLI returned no usable original status (exit ${lookup.status})`);
  const statusPath = join(outputDir, "status.json");
  await writeFile(statusPath, JSON.stringify(status) + "\n", { mode: 0o600, flag: "wx" });
  console.log(JSON.stringify(status));
  if (lookup.status !== 0 || status.status !== "confirmed" || status.transactionHash !== args.hash) {
    throw new Error("The original request has no confirmed application receipt");
  }

  console.log("$ Verify the original Stellar Testnet transfer against Soroban RPC and Horizon");
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL("./verify-stellar-receipt.mjs", import.meta.url)),
    ...receiptArguments.filter(name => name !== "journal-file").flatMap(name => [`--${name}`, args[name]]),
    "--journal-file", "-", "--origin", origin, "--status-file", statusPath,
  ], { input: journalBytes, encoding: "utf8", timeout: 100_000, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error(result.stderr?.trim() || "Receipt verification failed");
  const proof = JSON.parse(result.stdout);
  await writeFile(join(outputDir, "verified-receipt.json"), JSON.stringify(proof) + "\n",
    { mode: 0o600, flag: "wx" });
  console.log(JSON.stringify(proof));
  console.log("PASS | Original Stellar Testnet transfer confirmed.");
}

record().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
