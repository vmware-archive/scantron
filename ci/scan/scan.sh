#!/bin/bash

set -e

chmod +x ./scantron-binary/scantron

NMAP_RESULTS="results.xml"

# perform nmap scan
nmap -oX "$NMAP_RESULTS" -v --script ssl-enum-ciphers -sV -p - "$NMAP_RANGE"

# perform scantron scan
./scantron-binary/scantron bosh-scan \
  --nmap-results "$NMAP_RESULTS" \
  --director-url "$BOSH_ADDRESS" \
  --bosh-deployment "$BOSH_DEPLOYMENT" \
  --uaa-client "$BOSH_CLIENT_ID" \
  --uaa-client-secret "$BOSH_CLIENT_SECRET"
