#!/usr/bin/env node
// OPC UA over-writer (no external CLI deps; only needs node-opcua) - Pulses booleans or nudges numeric setpoints, then restores - Appends JSONL evidence
//
// Examples: node opcua-overwriter.mjs --endpoint opc.tcp://plc:4840 \ --node 'ns=1;s=heater_on' --pulseMs 1500 --restore \ --evidence /captures/opcua_phase3.jsonl
//
//   node opcua-overwriter.mjs --endpoint opc.tcp://plc:4840 \ --node 'ns=1;s=heater_setpoint' --nudgeAbs 0.5 --hold 5 --restore \ --evidence /captures/opcua_phase3.jsonl --user openplc 
//     --pass openplc
import fs from "fs"; import path from "path"; import opcua from "node-opcua"; const { OPCUAClient, AttributeIds, DataType, Variant, MessageSecurityMode, SecurityPolicy, UserTokenType
} = opcua;
// -------- tiny no-deps arg parser --------
function parseArgs(argv) { const out = {}; for (let i = 2; i < argv.length; i++) { let a = argv[i]; if (!a.startsWith("--")) continue; a = a.slice(2); let [k, v] = a.split("="); if (v === 
    undefined) {
      const nxt = argv[i + 1]; if (nxt && !nxt.startsWith("--")) { v = nxt; i++; } else v = "true";
    }
    out[k] = v;
  }
  return out;
}
const args = parseArgs(process.argv); const get = (k, def) => (k in args ? args[k] : def); const getNum = (k, def) => { if (!(k in args)) return def; const n = Number(args[k]); return 
  Number.isFinite(n) ? n : def;
};
const getBool = (k, def=false) => { if (!(k in args)) return def; const v = String(args[k]).toLowerCase(); return ["1","true","yes","y","on"].includes(v);
};
// -------- config --------
const endpoint = get("endpoint", "opc.tcp://plc:4840"); const nodeId = get("node", null); const user = get("user", ""); const pass = get("pass", ""); const evidence = get("evidence", ""); 
const nudge = getNum("nudge", NaN); // fraction of span if <1, or absolute if >=1 const nudgeAbs = getNum("nudgeAbs", NaN); // absolute EU (preferred for analog) const hold = getNum("hold", 
3); // seconds to hold analog const pulseMs = getNum("pulseMs", 1000); // boolean pulse ms const restore = getBool("restore", true); // auto-restore original value
// -------- helpers --------
function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); } function nowIso() { return new Date().toISOString(); } function logEv(obj) { if (!evidence) return; try { 
    ensureDir(path.dirname(evidence)); fs.appendFileSync(evidence, JSON.stringify({ ts: nowIso(), ...obj }) + "\n");
  } catch (e) {
    console.error("[!] evidence write failed:", e.message);
  }
}
const sleep = ms => new Promise(r => setTimeout(r, ms)); function isNumericType(dt) { return [ DataType.Byte, DataType.SByte, DataType.Int16, DataType.UInt16, DataType.Int32, 
    DataType.UInt32, DataType.Int64, DataType.UInt64, DataType.Float, DataType.Double
  ].includes(dt);
}
async function readMeta(session, nodeId) { const [dt, val, acc, uacc, bn] = await session.read([ { nodeId, attributeId: AttributeIds.DataType }, { nodeId, attributeId: AttributeIds.Value }, 
    { nodeId, attributeId: AttributeIds.AccessLevel }, { nodeId, attributeId: AttributeIds.UserAccessLevel }, { nodeId, attributeId: AttributeIds.BrowseName }
  ]); const builtIn = await session.getBuiltInDataType(nodeId).catch(()=>null); return { nodeId, browseName: bn?.value?.value?.name || String(nodeId), dataType: builtIn ?? dt?.value?.value, 
    value: val?.value?.value, access: acc?.value?.value ?? 0, uaccess: uacc?.value?.value ?? 0
  };
}
async function writeNode(session, nodeId, dataType, value) { const st = await session.write({ nodeId, attributeId: AttributeIds.Value, value: { value: new Variant({ dataType, value }) }
  });
  if (st.isNotGood()) { logEv({ event: "write_error", nodeId, status: st.toString() }); throw new Error(`Write failed: ${st.toString()}`);
  }
  logEv({ event: "write_ok", nodeId, value });
}
// -------- main --------
async function main() { if (!nodeId) { console.error("Usage: node opcua-overwriter.mjs --endpoint opc.tcp://plc:4840 --node 'ns=1;s=heater_on' [--user USER --pass PASS] [--pulseMs 1500] 
    [--nudgeAbs 0.5|--nudge 0.005] [--hold 5] [--restore] [--evidence /path/log.jsonl]"); process.exit(2);
  }
  let identity = { type: UserTokenType.Anonymous }; if (user && pass) identity = { type: UserTokenType.UserName, userName: user, password: pass }; else if (user || pass) { console.error("[!] 
  Provide BOTH --user and --pass, or neither."); process.exit(2); } const client = OPCUAClient.create({
    applicationName: "ICS-Testbed-Overwriter", securityPolicy: SecurityPolicy.Basic256Sha256, securityMode: MessageSecurityMode.SignAndEncrypt, endpointMustExist: false
    // Let node-opcua manage the default PKI under ~/.config/node-opcua-default-nodejs/PKI
  });
  console.log(`[+] Connecting (secure) to ${endpoint} as ${identity.type===UserTokenType.Anonymous?"anonymous":"user" } ...`); await client.connect(endpoint); const session = await 
  client.createSession(identity); logEv({ event: "session", endpoint, user: identity.type===UserTokenType.Anonymous?"anonymous":user }); console.log("[+] Session created"); const meta = 
  await readMeta(session, nodeId); console.log(`[i] Target: ${meta.nodeId} ${meta.browseName} DataType=${DataType[meta.dataType] ?? meta.dataType} cur=${JSON.stringify(meta.value)}`); const 
  rw = ((meta.access & 2) === 2) && ((meta.uaccess & 2) === 2); if (!rw) console.error("[!] Warning: target might be read-only for this user (write bits not set).");
  // Robust decision: inspect both declared type and actual value
  const val = meta.value; const looksBoolean = (typeof val === "boolean") || (meta.dataType === DataType.Boolean); const looksNumeric = Number.isFinite(Number(val)) || 
  isNumericType(meta.dataType); if (looksBoolean) {
    const from = !!val; const to = !from; console.log(`[>] Boolean pulse: ${from} -> ${to} (${pulseMs} ms) then restore=${restore}`); logEv({ event: "boolean_pulse", nodeId, from, to, 
    pulseMs }); await writeNode(session, nodeId, DataType.Boolean, to); await sleep(pulseMs); if (restore) {
      await writeNode(session, nodeId, DataType.Boolean, from); logEv({ event: "restore", nodeId, to: from });
    }
  } else if (looksNumeric) {
    const cur = Number(val); if (!Number.isFinite(cur)) throw new Error("Current value is not numeric/finite."); let delta; if (!Number.isNaN(nudgeAbs)) { delta = nudgeAbs;
    } else if (!Number.isNaN(nudge)) {
      // If <1 treat as fraction of span; with no EU range, assume ~20 EU span
      delta = (nudge < 1 ? 20 * nudge : nudge);
    } else {
      throw new Error("Provide --nudgeAbs (absolute units) or --nudge (fraction/absolute) for numeric targets.");
    }
    const goal = cur + delta; console.log(`[>] Analog nudge: ${cur} -> ${goal} (Δ=${goal-cur}), hold ${hold}s, restore=${restore}`); logEv({ event: "analog_nudge", nodeId, from: cur, to: 
    goal, delta: goal-cur, hold });
    // Pick a reasonable numeric type to write back
    const writeType = isNumericType(meta.dataType) ? meta.dataType : DataType.Double; await writeNode(session, nodeId, writeType, goal); await sleep(hold * 1000); if (restore) { await 
      writeNode(session, nodeId, writeType, cur); logEv({ event: "restore", nodeId, to: cur });
    }
  } else {
    console.error("[!] Target is neither Boolean nor numeric by value; nothing done.");
  }
  await session.close(); await client.disconnect(); console.log("[+] Done.", evidence ? `Evidence: ${evidence}` : "");
}
main().catch(async (err) => { console.error("[!] Error:", err.message || err); process.exit(1);
});
