#!/usr/bin/env node
/**
 * OPC UA enumerator — Secure-only + TOFU pinning (no insecure fallback)
 *
 * Flow:
 *  1) Ensure PKI; (re)generate client cert so applicationUri matches.
 *  2) Fetch serverCertificate via getEndpoints() (Security=None just for metadata).
 *  3) If --pinSha1 is provided, verify fingerprint; else print it (first-run convenience).
 *  4) Store the leaf in trusted/certs and (lab hack) in trusted/issuers/certs (to satisfy chain).
 *  5) Connect with SignAndEncrypt + Basic256Sha256 ONLY (no downgrade), then browse & read.
 *
 * Outputs: opcua_tags.json, opcua_snapshot.csv
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
import crypto from "crypto";
import { stringify as csvStringify } from "csv-stringify/sync";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

// ---------- CLI ----------
const argv = yargs(hideBin(process.argv))
  .option("endpoint", { alias: "e", type: "string", default: "opc.tcp://plc:4840" })
  .option("user", { alias: "u", type: "string", default: "", describe: "Username (omit to use anonymous)" })
  .option("pass", { alias: "p", type: "string", default: "" })
  .option("maxDepth", { type: "number", default: 5 })
  .option("maxPerBrowse", { type: "number", default: 150 })
  .option("pki", {
    type: "string",
    default: path.join(os.homedir(), ".config", "node-opcua-default-nodejs", "PKI"),
    describe: "Node-OPCUA PKI root"
  })
  .option("appName", { type: "string", default: "ICS-Testbed-Enumerator" })
  .option("appUri", { type: "string", describe: "Override applicationUri; default urn:<hostname>:<appName>" })
  .option("regenClientCert", { type: "boolean", default: true, describe: "Regenerate client cert so appUri matches" })
  .option("pinSha1", {
    type: "string",
    describe: "Expected SHA1 fingerprint of server leaf (format: AB:CD:... or abcd...)"
  })
  .strict()
  .help()
  .argv;

// ---------- Helpers ----------
async function ensurePKI(root) {
  const dirs = [
    "trusted/certs", "trusted/issuers/certs", "trusted/issuers/crl",
    "rejected/certs", "own/certs", "own/private"
  ].map(p => path.join(root, p));
  await Promise.all(dirs.map(d => fs.mkdir(d, { recursive: true })));
}
async function wipeOwn(root) {
  const own = path.join(root, "own");
  await fs.rm(own, { recursive: true, force: true }).catch(() => {});
}
function bytesToSha1Colon(buf) {
  const h = crypto.createHash("sha1").update(buf).digest("hex").toUpperCase();
  return h.match(/.{2}/g).join(":");
}
function normalizePin(s) { return s.replace(/:/g, "").toUpperCase(); }

async function getServerLeafDER(endpointUrl) {
  const tmp = OPCUAClient.create({
    securityMode: MessageSecurityMode.None,
    securityPolicy: SecurityPolicy.None,
    endpointMustExist: false
  });
  await tmp.connect(endpointUrl);
  const endpoints = await tmp.getEndpoints();
  await tmp.disconnect();
  if (!endpoints?.length) throw new Error("No endpoints advertised by server.");
  // Prefer Basic256Sha256 if offered, else first
  const pref = endpoints.find(e => (e.securityPolicyUri||"").includes("#Basic256Sha256")) || endpoints[0];
  const der = pref.serverCertificate;
  if (!der || der.length === 0) throw new Error("Endpoint missing serverCertificate.");
  return Buffer.from(der);
}

async function pinLeafToPKI(pkiRoot, leafDer) {
  const trusted = path.join(pkiRoot, "trusted", "certs", "plc-server.der");
  const issuers = path.join(pkiRoot, "trusted", "issuers", "certs", "plc-server.der");
  await fs.writeFile(trusted, leafDer);
  // Lab hack to satisfy chain checks in node-opcua without the intermediate:
  await fs.writeFile(issuers, leafDer).catch(() => {});
  return { trusted, issuers };
}

async function enumerateVariables(session, { maxDepth, maxPerBrowse }) {
  const queue = [{ nodeId: resolveNodeId("ObjectsFolder"), depth: 0 }];
  const seen = new Set();
  const out = [];
  while (queue.length) {
    const { nodeId, depth } = queue.shift();
    if (seen.has(nodeId.toString()) || depth > maxDepth) continue;
    seen.add(nodeId.toString());
    const res = await session.browse({
      nodeId,
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

function makeClient(appName, appUri) {
  return OPCUAClient.create({
    applicationName: appName,
    applicationUri: appUri,
    connectionStrategy: { initialDelay: 200, maxRetry: 2 },
    securityMode: MessageSecurityMode.SignAndEncrypt,
    securityPolicy: SecurityPolicy.Basic256Sha256,
    endpointMustExist: false,
    requestedSessionTimeout: 60000,
    keepAliveInterval: 3000
  });
}

// ---------- Main ----------
(async () => {
  const pkiRoot = argv.pki;
  await ensurePKI(pkiRoot);

  // Make client cert match our appUri to silence W06
  const host = os.hostname();
  const appName = argv.appName;
  const appUri = argv.appUri || `urn:${host}:${appName}`;
  if (argv.regenClientCert) {
    console.log(`[i] Regenerating client cert so applicationUri matches: ${appUri}`);
    await wipeOwn(pkiRoot);
    await ensurePKI(pkiRoot);
  }

  // TOFU: fetch server leaf & (optionally) verify fingerprint
  const leafDer = await getServerLeafDER(argv.endpoint);
  const fp = bytesToSha1Colon(leafDer);
  console.log(`[i] Server leaf SHA1: ${fp}`);
  if (argv.pinSha1) {
    const want = normalizePin(argv.pinSha1);
    const got = normalizePin(fp);
    if (want !== got) throw new Error(`Server fingerprint mismatch.\n  expected: ${argv.pinSha1}\n  got:      ${fp}`);
    console.log("[+] Fingerprint matches --pinSha1");
  } else {
    console.log("[i] Hint: next time you can pin with --pinSha1 \"" + fp + "\"");
  }

  // Store leaf into trust (and issuers for lab chain acceptance)
  const { trusted, issuers } = await pinLeafToPKI(pkiRoot, leafDer);
  console.log(`[+] Pinned server leaf to:\n    ${trusted}\n    ${issuers} (lab chain hack)`);

  // Connect SECURE ONLY
  const client = makeClient(appName, appUri);
  await client.connect(argv.endpoint);
  const identity = argv.user ? { type: "userName", userName: argv.user, password: argv.pass } : null;
  const session = await client.createSession(identity);
  console.log("[+] Secure session created");

  // Enumerate
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
  console.log("[+] Done (secure-only, TOFU pinned).");
})().catch(err => {
  console.error("[!] Secure-only run failed:", err?.message || err);
  process.exitCode = 1;
});
