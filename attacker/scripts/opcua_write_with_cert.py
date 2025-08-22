# opcua_write_with_cert.py
# usage: python3 opcua_write_with_cert.py opc.tcp://10.11.0.3:4840 'ns=1;s=max_temp' 75 /path/client_cert.pem /path/client_key.pem
import sys, asyncio
from asyncua import Client, ua
async def main(url, nodeid, number, cert, key):
    client = Client(url)
    client.set_security_string(f"Basic256Sha256,SignAndEncrypt,{cert},{key}")
    async with client:
        node = client.get_node(nodeid)
        await node.write_value(ua.Variant(float(number), ua.VariantType.Double))
        print("OK")
if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
