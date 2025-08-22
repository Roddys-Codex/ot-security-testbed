# opcua_write_secure.py
# usage: python3 opcua_write_secure.py opc.tcp://10.11.0.3:4840 'ns=1;s=on_button' true openplc openplc
import sys, asyncio
from asyncua import Client, ua

async def main(url, nodeid, val, user, pw):
    client = Client(url)
    client.set_security_string("Basic256Sha256,SignAndEncrypt")  # match server policy
    client.set_user(user); client.set_password(pw)
    async with client:
        node = client.get_node(nodeid)
        v = val.lower() in ("1","true","on","yes")
        await node.write_value(ua.Variant(v, ua.VariantType.Boolean))
        print("OK")

if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
