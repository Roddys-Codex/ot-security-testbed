# save as opcua_write_bool.py
# usage:
#   python3 opcua_write_bool.py opc.tcp://10.11.0.3:4840 ns=1;s=heater_on true
#   python3 opcua_write_bool.py opc.tcp://10.11.0.3:4840 ns=1;s=water_on false
import sys, asyncio
from asyncua import Client, ua

async def main(url, nodeid_str, value_str, user=None, pw=None):
    client = Client(url=url)
    if user and pw:
        client.set_user(user); client.set_password(pw)
    async with client:
        node = client.get_node(nodeid_str)
        val = value_str.lower() in ("1","true","on","yes")
        await node.write_value(ua.Variant(val, ua.VariantType.Boolean))
        # read back
        back = await node.read_value()
        print(f"Wrote {val} to {nodeid_str}; readback={back}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("usage: python3 opcua_write_bool.py <url> <nodeid> <true|false> [user] [pass]")
        sys.exit(1)
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], *(sys.argv[4:6] if len(sys.argv)>=6 else (None,None))))
