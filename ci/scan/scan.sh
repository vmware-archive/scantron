#!/bin/bash

set -e

chmod +x ./scantron-binary/scantron

CA_CERT="ca.crt"
NMAP_RESULTS="results.xml"

cat << EOF > "$CA_CERT"
$BOSH_CA_CERT
EOF

# perform nmap scan
timeout 10m nmap -oX "$NMAP_RESULTS" -sT --script ssl-enum-ciphers -sV -p - "$NMAP_RANGE"

# perform scantron scan
./scantron-binary/scantron bosh-scan \
  --database scantron-reports/reports.db \
  --nmap-results "$NMAP_RESULTS" \
  --director-url "$BOSH_ADDRESS" \
  --bosh-deployment "$BOSH_DEPLOYMENT" \
  --client "$BOSH_CLIENT_ID" \
  --client-secret "$BOSH_CLIENT_SECRET" \
  --ca-cert "$CA_CERT"
