# check_access_one.py
# usage: python3 check_access_one.py ns=1;s=on_button [user] [pass]
import sys, asyncio
from asyncua import Client, ua

async def main(nodeid, user=None, pw=None, url="opc.tcp://10.11.0.3:4840"):
    client = Client(url=url)
    if user and pw: client.set_user(user); client.set_password(pw)
    async with client:
        n = client.get_node(nodeid)
        v  = await n.read_value()
        ua_lev = await n.get_attribute(ua.AttributeIds.UserAccessLevel)
        lev    = ua_lev.Value.Value  # bit1=read, bit2=write
        print(f"Value={v}  UserAccessLevel={lev}  (write bit set? {bool(lev & 0b10)})")

if __name__ == "__main__":
    node = sys.argv[1]
    user = sys.argv[2] if len(sys.argv)>=3 else None
    pw   = sys.argv[3] if len(sys.argv)>=4 else None
    asyncio.run(main(node, user, pw))
