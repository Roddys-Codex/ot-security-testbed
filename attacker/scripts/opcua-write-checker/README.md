# Install deps if needed
npm i node-opcua csv-stringify yargs

# 1) Discover RW candidates (no writes yet)
node opcua-write-checker.mjs --endpoint opc.tcp://plc:4840 --dryRun

# 2) Prove write with *no-op writes* only
node opcua-write-checker.mjs --endpoint opc.tcp://plc:4840

# 3) Do tiny analog nudges (0.1% of span) + restore, and pulse booleans for 1s
node opcua-write-checker.mjs --endpoint opc.tcp://plc:4840 --nudge 0.001 --pulseMs 1000
