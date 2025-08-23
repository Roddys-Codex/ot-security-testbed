# list_writable.py
# usage: python3 list_writable.py opc.tcp://10.11.0.3:4840 [user] [pass]
import sys, asyncio
from asyncua import Client, ua

async def main(url, user=None, pw=None):
    client = Client(url=url)
    if user and pw: client.set_user(user); client.set_password(pw)
    async with client:
        objs = client.nodes.objects
        for n in await objs.get_children():
            bn = await n.read_browse_name()
            try:
                ual = await n.get_attribute(ua.AttributeIds.UserAccessLevel)
                user_access = ual.Value.Value  # bit 1=read, bit 2=write
                if user_access & 0b10:
                    print("Writable:", bn.Name, n)
            except: pass

if __name__ == "__main__":
    args = sys.argv[1:]
    asyncio.run(main(args[0], *(args[1:3] if len(args)>=3 else (None,None))))
