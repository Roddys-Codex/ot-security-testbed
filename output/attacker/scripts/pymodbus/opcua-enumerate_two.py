# save as opcua_enum.py ; run: python3 opcua_enum.py opc.tcp://10.11.0.3:4840
import sys, asyncio
from asyncua import Client, ua

async def main(url):
    async with Client(url=url) as client:
        # Anonymous by default; if it fails, try username/password below.
        root = client.nodes.root
        objects = client.nodes.objects
        print("Root children:")
        for ref in await root.get_references(0):  # 0=Hierarchical
            print("-", ref.BrowseName.Name, ref.NodeId)

        print("\nBrowse Objects:")
        for child in await objects.get_children():
            bn = await child.read_browse_name()
            print("-", bn.Name, child)

        # OPTIONAL: attempt to read a likely variable node if you know the NodeId
        # node = client.get_node("ns=2;s=SomeVariable") ; print(await node.read_value())

if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv)>1 else "opc.tcp://10.11.0.3:4840"))
