#!/usr/bin/env node
import { OPCUAClient, SecurityPolicy, MessageSecurityMode } from "node-opcua";
import fs from "fs/promises";
import path from "path";

const endpoint = process.env.OPCUA_ENDPOINT || "opc.tcp://plc:4840";
const PKI = process.env.NODEOPCUA_PKI || "/root/.config/node-opcua-default-nodejs/PKI";
const outDir = path.join(PKI, "trusted", "certs");

(async () => {
  await fs.mkdir(outDir, { recursive: true });
  const client = OPCUAClient.create({
    securityMode: MessageSecurityMode.None,
    securityPolicy: SecurityPolicy.None,
    endpointMustExist: false
  });
  await client.connect(endpoint);
  const endpoints = await client.getEndpoints();
  await client.disconnect();

  const preferred = endpoints.find(e => e.securityPolicyUri.includes("Basic256Sha256")) || endpoints[0];
  if (!preferred || !preferred.serverCertificate || preferred.serverCertificate.length === 0) {
    throw new Error("Could not retrieve server certificate from endpoints.");
  }
  const der = Buffer.from(preferred.serverCertificate);
  const outFile = path.join(outDir, "plc-server.der");
  await fs.writeFile(outFile, der);
  console.log(`[+] Wrote PLC server certificate to ${outFile}`);
})();
