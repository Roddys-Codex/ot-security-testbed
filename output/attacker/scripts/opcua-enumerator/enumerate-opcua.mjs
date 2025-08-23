#!/usr/bin/env node
/**
 * OPC UA Phase 1 enumerator — fully self-healing (no certificate headaches)
 *
 * What it does on startup:
 *  - Ensures PKI folders exist
 *  - Optionally regenerates client cert so applicationUri matches (quiet W06)
 *  - Auto-trusts PLC (TOFU): fetches serverCertificate via getEndpoints()
 *    and places it into trusted/certs; also copies leaf → issuers (lab fallback)
 *  - (Optional) Installs a provided issuer CA into trusted/issuers/certs
 *  - Attempts secure connect (SignAndEncrypt + Basic256Sha256), retries once
 *  - Final safety net: downgrade to None/None if secure connect still fails (lab only)
 *
 * Outputs:
 *   - opcua_tags.json
 *   - opcua_snapshot.csv
 */

import {
  OPCUAClient,
  MessageSecurityMode,
  SecurityPolicy,
  AttributeIds,
  NodeClass,
  resolveNodeId,
  BrowseDirection
} from "node-opcua";

import fs from "fs/promises";
import path from "path";
import os from "os";
import { stringify as csvStringify } from "csv-stringify/sync";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

// ---------- CLI ----------
const argv = yargs(hideBin(process.argv))
  .option("endpoint", { alias: "e", type: "string", default: "opc.tcp://plc:4840", describe: "OPC UA endpoint URL" })
  .option("user", { alias: "u", type: "string", default: "openplc", describe: "Username" })
  .option("pass", { alias: "p", type: "string", default: "openplc", describe: "Password" })
  .option("anonymous", { type: "boolean", default: false, describe: "Anonymous auth instead of username/password" })
  .option("policy", { choices: Object.keys(SecurityPolicy), default: "Basic256Sha256", describe: "SecurityPolicy" })
  .option("mode", { choices: Object.keys(MessageSecurityMode), default: "SignAndEncrypt", describe: "MessageSecurityMode" })
  .option("maxDepth", { type: "number", default: 5, describe: "Max browse recursion depth" })
  .option("maxPerBrowse", { type: "number", default: 150, describe: "Max references per browse chunk" })
  .option("pki", {
    type: "string",
    default: path.join(os.homedir(), ".config", "node-opcua-default-nodejs", "PKI"),
    describe: "Override Node-OPCUA PKI root"
  })
  .option("issuerCa", {
    type: "string",
    describe: "Path to intermediate CA file to trust (installed to trusted/issuers/certs)"
  })
  .option("autoFixCerts", {
    type: "boolean",
    default: true,
    describe: "Auto-fix trust: fetch PLC cert, sweep rejected->trusted, install issuer if provided"
  })
  .option("regenClientCert", {
    type: "boolean",
    default: true,
    describe: "Regenerate client cert (delete PKI/own) so applicationUri matches"
  })
  .option("fallbackNone", {
    type: "boolean",
    default: true,
    describe: "If secure connect still fails, fall back to SecurityPolicy.None / Mode.None"
  })
  .option("appName", {
    type: "string",
    default: "ICS-Testbed-Enumerator",
    describe: "Client applicationName"
  })
  .option("appUri", {
    type: "string",
    describe: "Override applicationUri; defaults to urn:<hostname>:<appName>"
  })
  .strict()
  .help()
  .argv;

// ---------- PKI helpers ----------
async function ensurePKI(root) {
  const dirs = [
    path.join(root, "trusted", "certs"),
    path.join(root, "trusted", "issuers", "certs"),
    path.join(root, "trusted", "issuers", "crl"),
    path.join(root, "rejected", "certs"),
    path.join(root, "own", "certs"),
    path.join(root, "own", "private")
  ];
  await Promise.all(dirs.map((d) => fs.mkdir(d, { recursive: true })));
}

async function wipeOwnIfRequested(root, enabled) {
  if (!enabled) return;
  const ownDir = path.join(root, "own");
  console.log(`[i] --regenClientCert: removing ${ownDir} to regenerate client certificate`);
  await fs.rm(ownDir, { recursive: true, force: true }).catch(() => {});
}

function pickPreferredEndpoint(endpoints, policyName) {
  const needle = `#${policyName}`; // e.g. "#Basic256Sha256"
  return endpoints.find((e) => (e.securityPolicyUri || "").includes(needle)) || endpoints[0];
}

async function dumpServerCertToTrusted(endpointUrl, pkiRoot, preferredPolicy) {
  // Connect with None/None just to read endpoints and fetch serverCertificate
  const tmpClient = OPCUAClient.create({
    securityMode: MessageSecurityMode.None,
    securityPolicy: SecurityPolicy.None,
    endpointMustExist: false
  });
  await tmpClient.connect(endpointUrl);
  const endpoints = await tmpClient.getEndpoints();
  await tmpClient.disconnect();

  if (!endpoints || endpoints.length === 0) throw new Error("No endpoints returned by server.");
  const ep = pickPreferredEndpoint(endpoints, preferredPolicy);
  const der = ep.serverCertificate;
  if (!der || der.length === 0) throw new Error("Endpoint has no serverCertificate.");

  const outDir = path.join(pkiRoot, "trusted", "certs");
  await fs.mkdir(outDir, { recursive: true });
  const outFile = path.join(outDir, "plc-server.der");
  await fs.writeFile(outFile, Buffer.from(der));
  return outFile;
}

async function sweepRejectedToTrusted(pkiRoot) {
  const candidates = [path.join(pkiRoot, "rejected", "certs"), path.join(pkiRoot, "rejected")];
  for (const dir of candidates) {
    try {
      const items = await fs.readdir(dir);
      for (const f of items) {
        const src = path.join(dir, f);
        try {
          const stat = await fs.stat(src);
          if (stat.isFile() && (f.endsWith(".der") || f.endsWith(".pem") || f.endsWith(".crt"))) {
            const dst = path.join(pkiRoot, "trusted", "certs", f);
            await fs.copyFile(src, dst).catch(() => {});
          }
        } catch {}
      }
    } catch {}
  }
}

async function installIssuerCA(pkiRoot, issuerPath) {
  if (!issuerPath) return null;
  const dst = path.join(pkiRoot, "trusted", "issuers", "certs", path.basename(issuerPath));
  await fs.copyFile(issuerPath, dst);
  return dst;
}

async function copyLeafToIssuers(pkiRoot, leafPath) {
  const dst = path.join(pkiRoot, "trusted", "issuers", "certs", path.basename(leafPath));
  await fs.copyFile(leafPath, dst).catch(() => {});
  return dst;
}

// ---------- OPC UA browse ----------
async function enumerateVariables(session, { maxDepth, maxPerBrowse }) {
  const queue = [{ nodeId: resolveNodeId("ObjectsFolder"), depth: 0 }];
  const seen = new Set();
  const out = [];

  while (queue.length) {
    const { nodeId, depth } = queue.shift();
    const key = nodeId.toString();
    if (seen.has(key) || depth > maxDepth) continue;
    seen.add(key);

    const res = await session.browse({
      nodeId,
      referenceTypeId: null,
      includeSubtypes: true,
      browseDirection: BrowseDirection.Forward,
      resultMask: 0x3f
    });

    const refs = res.references || [];
    for (let i = 0; i < refs.length; i += maxPerBrowse) {
      const chunk = refs.slice(i, i + maxPerBrowse);
      for (const r of chunk) {
        if (r.nodeClass === NodeClass.Variable) {
          const [val, dt] = await Promise.all([
            session.read({ nodeId: r.nodeId, attributeId: AttributeIds.Value }),
            session.read({ nodeId: r.nodeId, attributeId: AttributeIds.DataType })
          ]);
          out.push({
            nodeId: r.nodeId.toString(),
            browseName: r.browseName?.toString() || "",
            displayName: r.displayName?.text || "",
            dataTypeId: dt.value?.value?.toString() || "",
            value: val.value?.value,
            statusCode: val.statusCode?.toString(),
            sourceTimestamp: val.sourceTimestamp?.toISOString?.() || "",
            serverTimestamp: val.serverTimestamp?.toISOString?.() || ""
          });
        } else {
          queue.push({ nodeId: r.nodeId, depth: depth + 1 });
        }
      }
    }
  }
  return out;
}

// ---------- Connect with resilience ----------
function makeClientOpts(securityMode, securityPolicy, appName, appUri) {
  return {
    applicationName: appName,
    applicationUri: appUri,
    connectionStrategy: { initialDelay: 200, maxRetry: 3 },
    securityMode,
    securityPolicy,
    endpointMustExist: false,
    requestedSessionTimeout: 60000,
    keepAliveInterval: 3000
  };
}

async function trySecureConnect(endpoint, identity, appName, appUri) {
  const client = OPCUAClient.create(makeClientOpts(MessageSecurityMode.SignAndEncrypt, SecurityPolicy.Basic256Sha256, appName, appUri));
  await client.connect(endpoint);
  const session = await client.createSession(identity);
  return { client, session };
}

// ---------- Main ----------
(async () => {
  const pkiRoot = argv.pki;
  await ensurePKI(pkiRoot);

  // Prepare App Name / URI (prevents W06 warning; regen client cert if requested)
  const host = os.hostname();
  const appName = argv.appName;
  const appUri = argv.appUri || `urn:${host}:${appName}`;

  if (argv.regenClientCert) {
    await wipeOwnIfRequested(pkiRoot, true);
    await ensurePKI(pkiRoot);
  }

  // Auto-fix trust store (TOFU + optional issuer)
  if (argv.autoFixCerts) {
    await sweepRejectedToTrusted(pkiRoot);
    if (argv.issuerCa) {
      const dst = await installIssuerCA(pkiRoot, argv.issuerCa).catch(() => null);
      if (dst) console.log(`[+] Installed issuer CA -> ${dst}`);
    }
    const savedLeaf = await dumpServerCertToTrusted(argv.endpoint, pkiRoot, argv.policy).catch(() => null);
    if (savedLeaf) {
      console.log(`[+] Saved PLC server certificate to ${savedLeaf}`);
      // Lab fallback: also treat leaf as issuer if no issuer provided (fixes BadCertificateChainIncomplete quickly in labs)
      if (!argv.issuerCa) {
        const issuerDst = await copyLeafToIssuers(pkiRoot, savedLeaf);
        console.log(`[i] No --issuerCa provided; copied leaf to issuers (lab fallback): ${issuerDst}`);
      }
    }
  }

  // Identity
  const identity = argv.anonymous ? null : { type: "userName", userName: argv.user, password: argv.pass };

  // 1) Try secure connect (preferred)
  let client, session;
  try {
    console.log(`[+] Connecting (secure) to ${argv.endpoint} as ${argv.anonymous ? "anonymous" : argv.user} ...`);
    ({ client, session } = await trySecureConnect(argv.endpoint, identity, appName, appUri));
  } catch (err1) {
    const msg = String(err1 && err1.message || err1);
    console.warn(`[i] Secure connect failed (${msg}). Retrying once after re-fixing trust...`);

    // Re-sweep rejected and re-save leaf (covers race where cert dropped on first attempt)
    await sweepRejectedToTrusted(pkiRoot);
    const savedLeaf2 = await dumpServerCertToTrusted(argv.endpoint, pkiRoot, argv.policy).catch(() => null);
    if (savedLeaf2 && !argv.issuerCa) {
      await copyLeafToIssuers(pkiRoot, savedLeaf2).catch(() => {});
    }

    try {
      ({ client, session } = await trySecureConnect(argv.endpoint, identity, appName, appUri));
    } catch (err2) {
      if (!argv.fallbackNone) throw err2;
      console.warn("[i] Secure connect still failing. Falling back to None/None (lab-only) to complete enumeration.");

      // Final fallback: None/None
      const client2 = OPCUAClient.create(makeClientOpts(MessageSecurityMode.None, SecurityPolicy.None, appName, appUri));
      await client2.connect(argv.endpoint);
      const session2 = await client2.createSession(identity);
      client = client2; session = session2;
    }
  }

  console.log("[+] Session created");

  // Namespaces
  try {
    const arr = await session.readNamespaceArray();
    const namespaces = Array.isArray(arr) ? arr : (arr?.value?.value ?? []);
    if (namespaces.length) console.log(`[i] Namespaces: ${namespaces.join(", ")}`);
  } catch {}

  console.log(`[+] Browsing from ObjectsFolder (maxDepth=${argv.maxDepth}) ...`);
  const vars = await enumerateVariables(session, { maxDepth: argv.maxDepth, maxPerBrowse: argv.maxPerBrowse });
  console.log(`[+] Discovered Variables: ${vars.length}`);

  const jsonOut = "opcua_tags.json";
  await fs.writeFile(jsonOut, JSON.stringify({ endpoint: argv.endpoint, ts: new Date().toISOString(), vars }, null, 2));
  console.log(`[+] Wrote ${jsonOut}`);

  const headers = ["nodeId","browseName","displayName","dataTypeId","value","statusCode","sourceTimestamp","serverTimestamp"];
  const csv = csvStringify(vars.map(v => headers.reduce((o,k)=>({ ...o, [k]: v[k]}), {})), { header: true, columns: headers });
  const csvOut = "opcua_snapshot.csv";
  await fs.writeFile(csvOut, csv);
  console.log(`[+] Wrote ${csvOut}`);

  await session.close();
  await client.disconnect();
  console.log("[+] Done.");
})().catch((err) => {
  console.error("[!] Error:", err?.message || err);
  process.exitCode = 1;
});
