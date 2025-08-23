#!/usr/bin/env node
// opc-ua-enumerator.mjs (fixed)
// Read-only Phase-1 recon with correct securityMode handling + connection fallback.

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import pkg from 'node-opcua';

const {
  OPCUAClient,
  AttributeIds,
  MessageSecurityMode,
  SecurityPolicy,
  NodeClass,
  coerceNodeId,
} = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const i = (s) => console.log(`[i] ${s}`);
const p = (s) => console.log(`[+] ${s}`);
const w = (s) => console.warn(`[!] ${s}`);

function sha1(buf) { return crypto.createHash('sha1').update(buf).digest('hex').toUpperCase(); }
async function ensureDir(dir) { await fs.mkdir(dir, { recursive: true }); }
function toCsvRow(fields) {
  return fields.map(v=>{
    if (v === undefined || v === null) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s;
  }).join(',');
}

// ---- security helpers (FIX) ----
function modeToName(m) {
  if (typeof m === 'number') {
    if (m === MessageSecurityMode.SignAndEncrypt) return 'SignAndEncrypt';
    if (m === MessageSecurityMode.Sign)           return 'Sign';
    return 'None';
  }
  const s = String(m);
  if (/Encrypt/i.test(s)) return 'SignAndEncrypt';
  if (/Sign/i.test(s))    return 'Sign';
  return 'None';
}
function modeToEnum(name) {
  switch (name) {
    case 'SignAndEncrypt': return MessageSecurityMode.SignAndEncrypt;
    case 'Sign':           return MessageSecurityMode.Sign;
    default:               return MessageSecurityMode.None;
  }
}
function policyToEnum(policyNameOrUri) {
  const name = (policyNameOrUri || '').includes('#')
    ? policyNameOrUri.split('#').pop()
    : policyNameOrUri;
  switch (name) {
    case 'Basic256Sha256':         return SecurityPolicy.Basic256Sha256;
    case 'Basic256':               return SecurityPolicy.Basic256;
    case 'Basic128Rsa15':          return SecurityPolicy.Basic128Rsa15;
    case 'Aes128_Sha256_RsaOaep':  return SecurityPolicy.Aes128_Sha256_RsaOaep;
    case 'Aes256_Sha256_RsaPss':   return SecurityPolicy.Aes256_Sha256_RsaPss;
    default:                       return SecurityPolicy.None;
  }
}
function secPolicyRank(uri) {
  const order = [
    'http://opcfoundation.org/UA/SecurityPolicy#None',
    'http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15',
    'http://opcfoundation.org/UA/SecurityPolicy#Basic256',
    'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
    'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep',
    'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss',
  ];
  const idx = order.indexOf(uri);
  return idx < 0 ? 0 : idx;
}
function modeRank(mode) {
  const n = modeToName(mode);
  return n === 'SignAndEncrypt' ? 2 : (n === 'Sign' ? 1 : 0);
}
function pickBestEndpoint(endpoints, allowInsecure) {
  // Prefer strongest mode for a given policy; prefer stronger policy overall.
  const scored = endpoints.map(e => ({
    e,
    modeName: modeToName(e.securityMode),
    polName: (e.securityPolicyUri || '').split('#').pop(),
    score: modeRank(e.securityMode) * 10 + secPolicyRank(e.securityPolicyUri)
  })).sort((a,b)=>b.score-a.score);

  // avoid policy None unless explicitly allowed
  let best = scored.find(x => !x.e.securityPolicyUri.endsWith('#None'));
  if (!best && allowInsecure) best = scored[0];
  return (best || scored[0] || {}).e || null;
}

const argv = yargs(hideBin(process.argv))
  .option('endpoint', { alias:'e', type:'string', default:'opc.tcp://plc:4840' })
  .option('user',     { alias:'u', type:'string', default:'' })
  .option('pass',     { alias:'p', type:'string', default:'' })
  .option('pki',      { type:'string', default: path.join(process.env.HOME||'/root','.config','node-opcua-default-nodejs','PKI') })
  .option('regenClientCert', { type:'boolean', default:true })
  .option('allowInsecure',   { type:'boolean', default:false })
  .option('forcePolicy',     { type:'string', default:'' })
  .option('forceMode',       { type:'string', default:'' })
  .option('pattern',         { alias:'r', type:'string', default:'heater|water|drain|valve|pump|setpoint|mode|manual|auto|start|stop|enable' })
  .option('maxDepth',        { type:'number', default:5 })
  .option('maxPerBrowse',    { type:'number', default:200 })
  .option('evidence',        { type:'string', default:'/evidence' })
  .help().argv;

(async () => {
  const {
    endpoint, user, pass, pki, regenClientCert, allowInsecure,
    forcePolicy, forceMode, pattern, maxDepth, maxPerBrowse, evidence
  } = argv;

  await ensureDir(evidence);
  const jsonlPath = path.join(evidence, 'opcua_phase1_evidence.jsonl');
  const csvPath   = path.join(evidence, 'opcua_snapshot.csv');
  const certsDir  = path.join(evidence, 'certs');
  await ensureDir(certsDir);

  await fs.writeFile(csvPath, toCsvRow([
    'endpoint','nodeId','browseName','displayName','nodeClass',
    'dataTypeId','valueRank','access','userAccess','currentValue'
  ]) + '\n');

  const jsonFH = await fs.open(jsonlPath, 'a');

  // reset own cert if requested
  const ownDir = path.join(pki, 'own');
  if (regenClientCert) {
    try { await fs.rm(ownDir, { recursive:true, force:true }); i(`--regenClientCert: removed ${ownDir}`); } catch {}
  }
  await ensureDir(path.join(pki,'trusted','certs'));
  await ensureDir(path.join(pki,'trusted','issuers','certs'));

  // ----- discovery client (no security) -----
  const discClient = OPCUAClient.create({
    applicationName: 'ICS-Testbed-Enumerator',
    endpointMustExist: false,
    securityPolicy: SecurityPolicy.None,
    securityMode: MessageSecurityMode.None,
    certificateManager: { rootFolder: pki },
  });

  p(`Enumerating endpoints at ${endpoint} ...`);
  await discClient.connect(endpoint);
  const endpoints = await discClient.getEndpoints();
  await discClient.disconnect();

  for (const ep of endpoints) {
    await jsonFH.write(
      JSON.stringify({
        event:'endpoint',
        endpointUrl: ep.endpointUrl,
        securityPolicy: ep.securityPolicyUri,
        securityMode: modeToName(ep.securityMode),
        userTokens: ep.userIdentityTokens?.map(t=>t.tokenType),
        transport: ep.transportProfileUri,
        serverCertSha1: ep.serverCertificate ? sha1(Buffer.from(ep.serverCertificate)) : null,
      })+'\n'
    );
  }

  // ----- choose endpoint -----
  let chosen = null;
  if (forcePolicy || forceMode) {
    const polUri = forcePolicy ? (
      forcePolicy.startsWith('http') ? forcePolicy : `http://opcfoundation.org/UA/SecurityPolicy#${forcePolicy}`
    ) : null;
    chosen = endpoints.find(e =>
      (!polUri || e.securityPolicyUri === polUri) &&
      (!forceMode || modeToName(e.securityMode) === forceMode)
    ) || null;
    if (!chosen) w(`No endpoint matched forcePolicy=${forcePolicy} forceMode=${forceMode}; picking best available.`);
  }
  if (!chosen) chosen = pickBestEndpoint(endpoints, allowInsecure);
  if (!chosen) throw new Error('No endpoints discovered.');

  const chosenPolName  = (chosen.securityPolicyUri || '').split('#').pop();
  const chosenModeName = modeToName(chosen.securityMode);
  i(`Selected endpoint: policy=${chosenPolName}, mode=${chosenModeName}, url=${chosen.endpointUrl}`);

  // ----- save server cert -----
  if (chosen.serverCertificate && chosen.serverCertificate.length>0) {
    const der = Buffer.from(chosen.serverCertificate);
    const leafSha1 = sha1(der).match(/.{2}/g)?.join(':');
    const hostTag = (new URL(endpoint)).hostname.replace(/[^a-zA-Z0-9_.-]/g,'_');
    const derPath = path.join(certsDir, `${hostTag}-server.der`);
    await fs.writeFile(derPath, der);
    p(`Saved server certificate to ${derPath}`);
    await fs.writeFile(path.join(certsDir, `${hostTag}-server.sha1`), `${leafSha1}\n`);
    await jsonFH.write(JSON.stringify({ event:'server_cert', path:derPath, sha1:leafSha1 })+'\n');
    // trust (lab)
    await fs.writeFile(path.join(pki,'trusted','certs', `${hostTag}-server.der`), der);
    await fs.writeFile(path.join(pki,'trusted','issuers','certs', `${hostTag}-server.der`), der);
  }

  // ----- connect with fallback ladder (FIX) -----
  const who = user ? 'user' : 'anonymous';
  const candidates = [];

  // If endpoint policy is None -> only try None
  if (chosenPolName === 'None') {
    candidates.push({ pol: 'None', mode: 'None' });
  } else {
    // Secure policy: try S&E, then Sign; only try None if allowInsecure=true
    candidates.push({ pol: chosenPolName, mode: 'SignAndEncrypt' });
    candidates.push({ pol: chosenPolName, mode: 'Sign' });
    if (allowInsecure) candidates.push({ pol: 'None', mode: 'None' });
  }

  let client, session, connected = false, lastErr = null;
  for (const c of candidates) {
    try {
      p(`Connecting (${c.pol}/${c.mode}) to ${endpoint} as ${who} ...`);
      client = OPCUAClient.create({
        applicationName: 'ICS-Testbed-Enumerator',
        endpointMustExist: false,
        securityPolicy: policyToEnum(c.pol),
        securityMode: modeToEnum(c.mode),
        requestedSessionTimeout: 60*60*1000,
        connectionStrategy: { initialDelay: 200, maxRetry: 0 },
        certificateManager: { rootFolder: pki },
      });
      await client.connect(endpoint);
      session = await client.createSession(user ? { type: 1, userName: user, password: pass } : undefined);
      connected = true;
      break;
    } catch (err) {
      lastErr = err;
      try { if (client) await client.disconnect(); } catch {}
      client = undefined;
      i(`Connect failed for (${c.pol}/${c.mode}); trying next option...`);
    }
  }
  if (!connected) throw lastErr || new Error('Failed to open secure channel/session');

  await jsonFH.write(JSON.stringify({ event:'session', endpoint, as: who })+'\n');

  // ----- namespaces -----
  try {
    const nsArr = await session.readVariableValue('ns=0;i=2255');
    await jsonFH.write(JSON.stringify({ event:'namespaces', endpoint, array: nsArr?.value?.value })+'\n');
    p(`Namespaces: ${JSON.stringify(nsArr?.value?.value)}`);
  } catch (err) {
    w(`Failed to read NamespaceArray: ${err?.message || err}`);
  }

  // ----- browse & snapshot (read-only) -----
  const csvFH = await fs.open(csvPath, 'a');
  const rx = pattern ? new RegExp(pattern, 'i') : null;
  const startNode = coerceNodeId('ns=0;i=85');
  const q = [{ nodeId: startNode, depth: 0 }];
  const visited = new Set();

  async function readAttrs(nid) {
    const toRead = [
      { nodeId: nid, attributeId: AttributeIds.NodeClass },
      { nodeId: nid, attributeId: AttributeIds.BrowseName },
      { nodeId: nid, attributeId: AttributeIds.DisplayName },
      { nodeId: nid, attributeId: AttributeIds.DataType },
      { nodeId: nid, attributeId: AttributeIds.ValueRank },
      { nodeId: nid, attributeId: AttributeIds.AccessLevel },
      { nodeId: nid, attributeId: AttributeIds.UserAccessLevel },
    ];
    const dv = await session.read(toRead);
    const get = (idx) => dv[idx]?.value?.value;
    return {
      nodeClass: get(0),
      browseName: dv[1]?.value?.value?.toString?.() || '',
      displayName: dv[2]?.value?.value?.text || '',
      dataTypeId: dv[3]?.value?.value?.toString?.() || null,
      valueRank: get(4),
      access: get(5),
      uaccess: get(6),
    };
  }

  p(`Browsing from ObjectsFolder (maxDepth=${maxDepth}) ...`);
  while (q.length) {
    const { nodeId, depth } = q.shift();
    const key = String(nodeId.toString());
    if (visited.has(key)) continue;
    visited.add(key);

    const res = await session.browse({
      nodeId, includeSubtypes: true, browseDirection: 0, resultMask: 0x3F
    });
    const refs = res.references || [];

    for (const r of refs.slice(0, maxPerBrowse)) {
      const childId = r.nodeId;
      const sChild = childId.toString();
      if (visited.has(sChild)) continue;

      let attrs = {};
      try { attrs = await readAttrs(childId); } catch {}

      let curVal = null;
      if (attrs.nodeClass === NodeClass.Variable) {
        try {
          const dv = await session.readVariableValue(childId);
          if (dv?.statusCode?.name === 'Good') curVal = dv.value?.value;
        } catch {}
      }

      const rec = {
        event: 'inspect',
        nodeId: sChild,
        browseName: attrs.browseName || r.browseName?.toString?.() || '',
        displayName: attrs.displayName || r.displayName?.toString?.() || '',
        nodeClass: attrs.nodeClass,
        dataTypeId: attrs.dataTypeId,
        valueRank: attrs.valueRank,
        access: attrs.access,
        uaccess: attrs.uaccess,
        currentValue: curVal,
      };

      if (!rx || rx.test(rec.browseName) || rx.test(rec.displayName)) {
        await jsonFH.write(JSON.stringify(rec)+'\n');
      }
      if (attrs.nodeClass === NodeClass.Variable) {
        await csvFH.write(toCsvRow([
          endpoint, rec.nodeId, rec.browseName, rec.displayName, rec.nodeClass,
          rec.dataTypeId, rec.valueRank, rec.access, rec.uaccess,
          (typeof curVal === 'object' ? JSON.stringify(curVal) : curVal)
        ]) + '\n');
      }

      if (depth < maxDepth) q.push({ nodeId: childId, depth: depth + 1 });
    }
  }

  await csvFH.close();
  p('Done.');
  await jsonFH.write(JSON.stringify({ event:'done', endpoint, visited: visited.size })+'\n');
  await jsonFH.close();
  await session.close();
  await client.disconnect();

})().catch((err) => {
  w(`Error: ${err?.message || err}`);
  process.exit(1);
});
