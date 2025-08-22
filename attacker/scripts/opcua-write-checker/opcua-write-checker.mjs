#!/usr/bin/env node
/**
 * opcua-write-checker.mjs
 * Secure-only (SignAndEncrypt + Basic256Sha256) write capability validator with TOFU pinning.
 *
 * - Filters nodes by browseName regex
 * - Reads AccessLevel/UserAccessLevel/DataType
 * - No-op write (write same value) to prove write capability
 * - Optional --nudge for tiny bounded analog nudges (auto-restores)
 * - Logs JSON lines to write_check_log.jsonl
 */
import {
  OPCUAClient, MessageSecurityMode, SecurityPolicy,
  AttributeIds, NodeClass, resolveNodeId, BrowseDirection, DataType, Variant
} from "node-opcua";
import fs from "fs/promises";
import path from "path";
import os from "os";
import crypto from "crypto";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

// ---------- CLI ----------
const argv = yargs(hideBin(process.argv))
  .option("endpoint", { alias: "e", default: "opc.tcp://plc:4840" })
  .option("user", { alias: "u", default: "", describe: "Username (omit => anonymous)" })
  .option("pass", { alias: "p", default: "" })
  .option("pattern", { alias: "r", default: "mode|manual|auto|start|stop|enable|setpoint|sp|output|valve|pump|heater", describe: "Regex (i) for browseName filter" })
  .option("maxDepth", { type: "number", default: 5 })
  .option("maxPerBrowse", { type: "number", default: 150 })
  .option("pki", { default: path.join(os.homedir(), ".config", "node-opcua-default-nodejs", "PKI") })
  .option("regenClientCert", { type: "boolean", default: true })
  .option("pinSha1", { type: "string", describe: "Expected SHA1 of server leaf (AB:CD:..)" })
  .option("nudge", { type: "number", describe: "Analog nudge as fraction of span (e.g., 0.001 = 0.1%). Default: NO nudging." })
  .option("pulseMs", { type: "number", default: 1000, describe: "Boolean pulse duration (ms) if --nudge and boolean" })
  .option("dryRun", { type: "boolean", default: false, describe: "Discover + report only, no writes" })
  .strict().help().argv;

// ---------- TOFU helpers ----------
async function ensurePKI(root) {
  const dirs = ["trusted/certs","trusted/issuers/certs","trusted/issuers/crl","own/certs","own/private"];
  await Promise.all(dirs.map(d => fs.mkdir(path.join(root,d), { recursive: true })));
}
async function wipeOwn(root) {
  await fs.rm(path.join(root,"own"), { recursive: true, force: true }).catch(()=>{});
}
function sha1Colon(buf){return crypto.createHash("sha1").update(buf).digest("hex").toUpperCase().match(/.{2}/g).join(":");}
function norm(s){return s.replace(/:/g,"").toUpperCase();}

async function getServerLeafDER(endpointUrl) {
  const tmp = OPCUAClient.create({ securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None, endpointMustExist:false });
  await tmp.connect(endpointUrl);
  const eps = await tmp.getEndpoints();
  await tmp.disconnect();
  const ep = eps.find(e => (e.securityPolicyUri||"").includes("#Basic256Sha256")) || eps[0];
  if (!ep?.serverCertificate?.length) throw new Error("No serverCertificate.");
  return Buffer.from(ep.serverCertificate);
}
async function pinLeaf(pkiRoot, der) {
  const t = path.join(pkiRoot,"trusted/certs/plc-server.der");
  const i = path.join(pkiRoot,"trusted/issuers/certs/plc-server.der"); // lab hack to satisfy chain
  await fs.writeFile(t, der); await fs.writeFile(i, der).catch(()=>{});
  return {t,i};
}

// ---------- OPC UA utilities ----------
async function browseAll(session, maxDepth, maxPerBrowse) {
  const out = [];
  const queue = [{ nodeId: resolveNodeId("ObjectsFolder"), depth: 0 }];
  const seen = new Set();
  while(queue.length){
    const {nodeId, depth} = queue.shift();
    if (seen.has(nodeId.toString()) || depth>maxDepth) continue;
    seen.add(nodeId.toString());
    const res = await session.browse({ nodeId, includeSubtypes:true, browseDirection: BrowseDirection.Forward, resultMask: 0x3f });
    const refs = res.references || [];
    for (let i=0;i<refs.length;i+=maxPerBrowse){
      const chunk = refs.slice(i,i+maxPerBrowse);
      for (const r of chunk){
        if (r.nodeClass===NodeClass.Variable) out.push(r);
        else queue.push({ nodeId: r.nodeId, depth: depth+1 });
      }
    }
  }
  return out;
}

function hasWriteFlag(level){ return (level & 0x02) === 0x02; }

async function readAttrs(session, nodeId, attrs){
  const nodesToRead = attrs.map(a => ({ nodeId, attributeId: AttributeIds[a] }));
  const results = await session.read(nodesToRead);
  const out = {};
  attrs.forEach((a,idx)=> out[a]=results[idx]);
  return out;
}

async function readAnalogRanges(session, varNodeId){
  // Find HasProperty -> EURange / InstrumentRange
  const b = await session.browse(varNodeId);
  const props = (b.references||[]).filter(r => (r.browseName?.name||r.browseName?.toString?.()||"").match(/^(EU|Instrument)Range$/));
  const ranges = {};
  for (const p of props){
    const dv = await session.read({ nodeId: p.nodeId, attributeId: AttributeIds.Value });
    ranges[p.browseName.toString()] = dv?.value?.value; // {low, high}
  }
  return ranges; // e.g., { EURange:{low,high}, InstrumentRange:{low,high} }
}

function clamp(v, low, high){ return Math.max(low, Math.min(high, v)); }

async function safeWriteSame(session, nodeId, currentVariant){
  // Write the exact same variant back (no-op write)
  const st = await session.writeSingleNode(nodeId, currentVariant);
  return st.toString();
}

async function safeNudge(session, nodeId, currentVariant, nudgeFrac, ranges, pulseMs){
  const now = currentVariant?.value;
  const dt = currentVariant?.dataType;

  // Booleans: short pulse
  if (dt === DataType.Boolean){
    const onVal = new Variant({ dataType: DataType.Boolean, value: !now });
    const offVal = new Variant({ dataType: DataType.Boolean, value: now });
    const st1 = await session.writeSingleNode(nodeId, onVal);
    await new Promise(r=>setTimeout(r,pulseMs));
    const st2 = await session.writeSingleNode(nodeId, offVal);
    return { st1: st1.toString(), st2: st2.toString(), newValue: now };
  }

  // Numerics: tiny bounded nudge
  if ([DataType.Double,DataType.Float,DataType.Int16,DataType.Int32,DataType.Int64,DataType.UInt16,DataType.UInt32,DataType.UInt64,DataType.SByte,DataType.Byte].includes(dt)){
    const curr = Number(now);
    let low = Number.NEGATIVE_INFINITY, high = Number.POSITIVE_INFINITY;
    if (ranges?.EURange){ low = ranges.EURange.low; high = ranges.EURange.high; }
    else if (ranges?.InstrumentRange){ low = ranges.InstrumentRange.low; high = ranges.InstrumentRange.high; }

    // default span if none advertised
    if (!isFinite(low) || !isFinite(high) || low>=high){
      low = curr - Math.max(Math.abs(curr)*0.05, 1); // ±5% or ±1
      high = curr + Math.max(Math.abs(curr)*0.05, 1);
    }
    const span = high - low;
    const delta = Math.max(span * (nudgeFrac||0),  Number.EPSILON);
    const target = clamp(curr + delta, low, high);

    const typed = new Variant({ dataType: dt, value: (dt===DataType.Int16||dt===DataType.Int32||dt===DataType.Int64||dt===DataType.UInt16||dt===DataType.UInt32||dt===DataType.UInt64||dt===DataType.SByte||dt===DataType.Byte) ? Math.trunc(target) : target });
    const restore = new Variant({ dataType: dt, value: now });

    const st1 = await session.writeSingleNode(nodeId, typed);
    await new Promise(r=>setTimeout(r,500));
    const st2 = await session.writeSingleNode(nodeId, restore);
    return { st1: st1.toString(), st2: st2.toString(), newValue: now, target };
  }

  return { error: "Unsupported DataType for nudge", dataType: DataType[currentVariant?.dataType] };
}

// ---------- Main ----------
(async ()=>{
  // PKI prep + client cert matching ApplicationUri (quiet W06)
  const PKI = argv.pki;
  await ensurePKI(PKI);
  if (argv.regenClientCert){ await wipeOwn(PKI); await ensurePKI(PKI); }

  // TOFU pinning of server leaf
  const der = await getServerLeafDER(argv.endpoint);
  const fp = sha1Colon(der);
  console.log(`[i] Server leaf SHA1: ${fp}`);
  if (argv.pinSha1 && norm(argv.pinSha1)!==norm(fp)) throw new Error(`Fingerprint mismatch. Expected ${argv.pinSha1}, got ${fp}`);
  const t = await pinLeaf(PKI, der);
  console.log(`[+] Pinned server cert at: ${t.t} | issuers(lab): ${t.i}`);

  // Secure-only client
  const host = os.hostname(), appName = "ICS-Testbed-WriteChecker", appUri = `urn:${host}:${appName}`;
  const client = OPCUAClient.create({
    applicationName: appName, applicationUri: appUri,
    connectionStrategy: { initialDelay: 200, maxRetry: 2 },
    securityMode: MessageSecurityMode.SignAndEncrypt,
    securityPolicy: SecurityPolicy.Basic256Sha256,
    endpointMustExist: false
  });
  await client.connect(argv.endpoint);
  const identity = argv.user ? { type:"userName", userName: argv.user, password: argv.pass } : null;
  const session = await client.createSession(identity);
  console.log("[+] Secure session created");

  // Find candidate Variables
  const regex = new RegExp(argv.pattern, "i");
  const vars = (await browseAll(session, argv.maxDepth, argv.maxPerBrowse))
    .filter(v => regex.test(v.browseName?.toString?.()||""));

  console.log(`[i] Candidates matching /${argv.pattern}/i: ${vars.length}`);

  const logPath = "write_check_log.jsonl";
  const log = async (o)=> fs.appendFile(logPath, JSON.stringify(o)+"\n");

  for (const v of vars){
    const nodeId = v.nodeId;
    const m = await readAttrs(session, nodeId, ["AccessLevel","UserAccessLevel","DataType","Value"]);
    const access = m.AccessLevel?.value?.value ?? 0;
    const uaccess = m.UserAccessLevel?.value?.value ?? 0;
    const dataTypeId = m.DataType?.value?.value;
    const current = m.Value?.value; // Variant

    const writable = hasWriteFlag(access) && hasWriteFlag(uaccess);
    const base = {
      nodeId: nodeId.toString(),
      browseName: v.browseName?.toString()||"",
      displayName: v.displayName?.text||"",
      access, uaccess, dataTypeId, dataType: DataType[dataTypeId],
      currentValue: current?.value
    };

    await log({ event:"inspect", ...base });

    if (!writable){
      console.log(`[-] RO: ${base.browseName} (${base.nodeId})`);
      continue;
    }

    console.log(`[+] RW: ${base.browseName} (${base.nodeId}) — attempting ${argv.dryRun?"DRY":"no-op write"} ...`);

    if (!argv.dryRun){
      // No-op write
      const stNoop = await safeWriteSame(session, nodeId, current);
      await log({ event:"noop_write", status: stNoop, ...base });

      // Optional tiny nudge + restore
      if (argv.nudge){
        const ranges = await readAnalogRanges(session, nodeId);
        const res = await safeNudge(session, nodeId, current, argv.nudge, ranges, argv.pulseMs);
        await log({ event:"nudge", result: res, ranges, ...base });
        console.log(`[i] Nudge result: ${JSON.stringify(res)}`);
      }
    }
  }

  await session.close(); await client.disconnect();
  console.log(`[+] Done. Evidence in ${logPath}`);
})().catch(e=>{ console.error("[!] Error:", e?.message||e); process.exitCode=1; });
