#!/bin/bash

set -e

chmod +x ./scantron-binary/scantron

CA_CERT="ca.crt"

cat << EOF > "$CA_CERT"
$BOSH_CA_CERT
EOF

./scantron-binary/scantron bosh-scan \
  --database scantron-reports/reports.db \
  --director-url "$BOSH_ADDRESS" \
  --bosh-deployment "$BOSH_DEPLOYMENT" \
  --client "$BOSH_CLIENT_ID" \
  --client-secret "$BOSH_CLIENT_SECRET" \
  --ca-cert "$CA_CERT"
