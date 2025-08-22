#!/usr/bin/env node
// enumerate-opcua.mjs
// Secure OPC UA enumerator: browses Variables, saves a tag catalog + value snapshot.
// Requires your CA cert (trust anchor) in:  ~/.config/node-opcua-default-nodejs/PKI/trusted/certs/
// And CA CRL (recommended) in:               .../trusted/crl/ (and/or .../trusted/issuers/crl/)

import {
  OPCUAClient, MessageSecurityMode, SecurityPolicy,
  AttributeIds, NodeClass, BrowseDirection, resolveNodeId
} from "node-opcua";
import fs from "fs/promises";
import path from "path";
import os from "os";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const argv = yargs(hideBin(process.argv))
  .option("endpoint", { alias: "e", default: "opc.tcp://plc:4840" })
  .option("user", { alias: "u", type: "string", default: "", describe: "Username (omit => anonymous)" })
  .option("pass", { alias: "p", type: "string", default: "" })
  .option("maxDepth", { type: "number", default: 5 })
  .option("maxPerBrowse", { type: "number", default: 150 })
  .option("outfileJson", { type: "string", default: "opcua_tags.json" })
  .option("outfileCsv", { type: "string", default: "opcua_snapshot.csv" })
  .option("pki", { type: "string", default: path.join(os.homedir(), ".config", "node-opcua-default-nodejs", "PKI") })
  .option("regenClientCert", { type: "boolean", default: false, describe: "Delete PKI/own to regenerate a client cert (fixes W06 warning)" })
  .strict().help().argv;

async function ensureDirs(...dirs){ await Promise.all(dirs.map(d => fs.mkdir(d, { recursive: true }))); }
async function wipeOwn(pki){ await fs.rm(path.join(pki,"own"), { recursive:true, force:true }).catch(()=>{}); }

async function browseAll(session, maxDepth, maxPerBrowse){
  const out = [];
  const queue = [{ nodeId: resolveNodeId("ObjectsFolder"), depth: 0, path: "Objects" }];
  const seen = new Set();
  while (queue.length){
    const cur = queue.shift();
    if (seen.has(cur.nodeId.toString()) || cur.depth > maxDepth) continue;
    seen.add(cur.nodeId.toString());

    const res = await session.browse({ nodeId: cur.nodeId, browseDirection: BrowseDirection.Forward, includeSubtypes:true, resultMask: 0x3f });
    const refs = res.references || [];
    for (let i=0;i<refs.length;i+=maxPerBrowse){
      for (const r of refs.slice(i,i+maxPerBrowse)){
        const rPath = `${cur.path}/${r.browseName?.toString?.()||""}`;
        if (r.nodeClass === NodeClass.Variable) out.push({ ...r, path: rPath });
        else queue.push({ nodeId: r.nodeId, depth: cur.depth+1, path: rPath });
      }
    }
  }
  return out;
}

function toCsvLine(a){ return a.map(v => {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s;
}).join(",");}

(async ()=>{
  // PKI prep
  const PKI = argv.pki;
  await ensureDirs(PKI, path.join(PKI,"trusted","certs"), path.join(PKI,"trusted","crl"));
  if (argv.regenClientCert){ console.log("[i] --regenClientCert: wiping PKI/own to regenerate client cert"); await wipeOwn(PKI); }

  // Client (secure-only)
  const host = os.hostname();
  const appName = "ICS-Testbed-Enumerator";
  const appUri  = `urn:${host}:${appName}`;
  const client = OPCUAClient.create({
    applicationName: appName,
    applicationUri: appUri,
    connectionStrategy: { initialDelay: 200, maxRetry: 2 },
    securityMode: MessageSecurityMode.SignAndEncrypt,
    securityPolicy: SecurityPolicy.Basic256Sha256,
    endpointMustExist: false
  });

  console.log(`[+] Connecting (secure) to ${argv.endpoint} as ${argv.user ? "user '"+argv.user+"'" : "anonymous"} ...`);
  await client.connect(argv.endpoint);
  const session = await client.createSession(argv.user ? { type:"userName", userName: argv.user, password: argv.pass } : undefined);
  console.log("[+] Secure session created");

  // Namespaces
  const ns = await session.readNamespaceArray?.() || await session.getNamespaceArray?.();
  if (ns) console.log("[i] Namespaces:", ns.join(", "));

  // Browse Variables
  console.log(`[+] Browsing from ObjectsFolder (maxDepth=${argv.maxDepth}) ...`);
  const vars = await browseAll(session, argv.maxDepth, argv.maxPerBrowse);

  // Read Values (snapshot)
  const nodesToRead = vars.map(v => ({ nodeId: v.nodeId, attributeId: AttributeIds.Value }));
  const dv = nodesToRead.length ? await session.read(nodesToRead) : [];
  const now = new Date().toISOString();

  // Build JSON catalog
  const catalog = vars.map((v, i)=>({
    browseName: v.browseName?.toString?.()||"",
    displayName: v.displayName?.text||"",
    nodeId: v.nodeId?.toString?.()||"",
    path: v.path,
    value: dv[i]?.value?.value,
    statusCode: dv[i]?.statusCode?.toString?.(),
    sourceTimestamp: dv[i]?.sourceTimestamp||null,
    serverTimestamp: dv[i]?.serverTimestamp||null
  }));

  await fs.writeFile(argv.outfileJson, JSON.stringify({ generatedAt: now, count: catalog.length, vars: catalog }, null, 2));
  console.log(`[+] Discovered Variables: ${catalog.length}`);
  console.log(`[+] Wrote ${argv.outfileJson}`);

  // CSV snapshot (nodeId,browseName,path,value,sourceTimestamp,serverTimestamp,statusCode)
  const header = ["nodeId","browseName","path","value","sourceTimestamp","serverTimestamp","statusCode"];
  const lines = [toCsvLine(header)];
  for (const c of catalog){
    lines.push(toCsvLine([
      c.nodeId, c.browseName, c.path,
      (typeof c.value === "object" ? JSON.stringify(c.value) : c.value),
      c.sourceTimestamp || "", c.serverTimestamp || "", c.statusCode || ""
    ]));
  }
  await fs.writeFile(argv.outfileCsv, lines.join("\n"));
  console.log(`[+] Wrote ${argv.outfileCsv}`);

  await session.close(); await client.disconnect();
  console.log("[+] Done.");
})().catch(err=>{ console.error("[!] Error:", err?.message || err); process.exitCode = 1; });
