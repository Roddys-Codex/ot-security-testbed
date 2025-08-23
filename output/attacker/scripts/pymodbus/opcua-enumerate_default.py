# save as opcua_enum_auth.py ; run: python3 opcua_enum_auth.py opc.tcp://10.11.0.3:4840 openplc openplc
import sys, asyncio
from asyncua import Client, ua

async def main(url, user, pw):
    client = Client(url=url)
    client.set_user(user); client.set_password(pw)
    async with client:
        objs = client.nodes.objects
        for child in await objs.get_children():
            bn = await child.read_browse_name()
            print("-", bn.Name, child)

if __name__ == "__main__":
    url = sys.argv[1]; user = sys.argv[2]; pw = sys.argv[3]
    asyncio.run(main(url, user, pw))
