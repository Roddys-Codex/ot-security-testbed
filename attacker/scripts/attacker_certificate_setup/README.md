ON THE HOST

PLC="ot-security-testbed-openplc-1"
ATTACKER="<your-attacker-container>"

# Copy CA cert (and CRL if present) from PLC → HOST /tmp
docker cp "$PLC":/path/to/ca.crt /tmp/ca.crt
# docker cp "$PLC":/path/to/ca.crl /tmp/ca.crl   # if it exists

# Then HOST → ATTACKER
docker cp /tmp/ca.crt "$ATTACKER":/tmp/ca.crt
[ -f /tmp/ca.crl ] && docker cp /tmp/ca.crl "$ATTACKER":/tmp/ca.crl

INSIDE THE ATTACKER CONTAINER

PKI="/root/.config/node-opcua-default-nodejs/PKI"
mkdir -p "$PKI/trusted/certs" "$PKI/trusted/crl" \
         "$PKI/trusted/issuers/certs" "$PKI/trusted/issuers/crl"

cp /tmp/ca.crt "$PKI/trusted/certs/plc-root-ca.crt"
[ -f /tmp/ca.crl ] && cp /tmp/ca.crl "$PKI/trusted/crl/plc-root-ca.crl" && cp /tmp/ca.crl "$PKI/trusted/issuers/crl/plc-root-ca.crl"

openssl x509 -inform der -in "$PKI/trusted/certs/plc-server.der" -out /tmp/plc-server.pem
openssl verify -CAfile "$PKI/trusted/certs/plc-root-ca.crt" \
               -crl_check -CRLfile "$PKI/trusted/crl/plc-root-ca.crl" \
               /tmp/plc-server.pem

cd /scripts/opcua-write-checker
node opcua-write-checker.mjs --endpoint opc.tcp://plc:4840 --dryRun

