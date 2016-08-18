     .d8888b.   .d8888b.        d8888 888b    888 88888888888 8888888b.   .d88888b.  888b    888
    d88P  Y88b d88P  Y88b      d88888 8888b   888     888     888   Y88b d88P" "Y88b 8888b   888
    Y88b.      888    888     d88P888 88888b  888     888     888    888 888     888 88888b  888
     "Y888b.   888           d88P 888 888Y88b 888     888     888   d88P 888     888 888Y88b 888
        "Y88b. 888          d88P  888 888 Y88b888     888     8888888P"  888     888 888 Y88b888
          "888 888    888  d88P   888 888  Y88888     888     888 T88b   888     888 888  Y88888
    Y88b  d88P Y88b  d88P d8888888888 888   Y8888     888     888  T88b  Y88b. .d88P 888   Y8888
     "Y8888P"   "Y8888P" d88P     888 888    Y888     888     888   T88b  "Y88888P"  888    Y888

### BUILDING

1. Install glide, the vendor package manager: https://github.com/Masterminds/glide
1. `go get github.com/pivotal-cf/scantron`
1. `cd $GOPATH/src/github.com/pivotal-cf/scantron && glide install`

### SYNOPSIS

    scantron --nmap-results=PATH [ --inventory=PATH ] [ --director-url=URL --director-username=USERNAME --director-password=PASSWORD --bosh-deployment=DEPLOYMENT_NAME ] [ --gateway-username=USERNAME --gateway-host=URL --gateway-private-key=PATH ] [ --uaa-client=OAUTH_CLIENT --uaa-client-secret=OAUTH_CLIENT_SECRET ]

### OPTIONS

    --nmap-results=PATH                        Path to nmap results XML (See GENERATING NMAP RESULTS)
    --inventory=PATH                           Path to inventory XML (See GENERATING INVENTORY)

    --director-url=URL                         BOSH Director URL
    --director-username=USERNAME               BOSH Director username
    --director-password=PASSWORD               BOSH Director password
    --bosh-deployment=DEPLOYMENT_NAME          BOSH Deployment

    --gateway-username=USERNAME                BOSH VM gateway username
    --gateway-host=URL                         BOSH VM gateway host
    --gateway-private-key=PATH                 BOSH VM gateway private key

    --uaa-client=OAUTH_CLIENT                  UAA Client
    --uaa-client-secret=OAUTH_CLIENT_SECRET    UAA Client Secret

### GENERATING NMAP RESULTS

Use nmap to scan 10.0.0.1 through 10.0.0.6, outputting the results as XML:

    nmap -oX results.xml -sV -n -p - 10.0.0.1-6

### GENERATING INVENTORY (SKIP IF TARGETING BOSH)

    hosts:
    - name: cell
      username: user
      password: secret
      addresses:
      - 10.0.0.1
      - 10.0.0.2
      - 10.0.0.3

    - name: brain
      username: user
      password: secretz
      addresses:
      - 10.0.0.4
      - 10.0.0.5
      - 10.0.0.6

### EXAMPLES

    # Direct scanning
    scantron --nmap-results results.xml --inventory inventory.yml

    # BOSH
    scantron --nmap-results results.xml \
      --director-url=URL \
      --director-username=USERNAME \
      --director-password=PASSWORD \
      --bosh-deployment=DEPLOYMENT_NAME

    # BOSH with gateway
    scantron --nmap-results results.xml \
      --director-url=URL \
      --director-username=USERNAME \
      --director-password=PASSWORD \
      --bosh-deployment=DEPLOYMENT_NAME \
      --gateway-username=USERNAME \
      --gateway-host=URL \
      --gateway-private-key=PATH

    # BOSH with gateway and UAA
    scantron --nmap-results results.xml \
      --director-url=URL \
      --director-username=USERNAME \
      --director-password=PASSWORD \
      --bosh-deployment=DEPLOYMENT_NAME \
      --gateway-username=USERNAME \
      --gateway-host=URL \
      --gateway-private-key=PATH \
      --uaa-client=OAUTH_CLIENT \
      --uaa-client-secret=OAUTH_CLIENT_SECRET

### EXAMPLE OUTPUT

    IP Address  Job       Service       Port   SSL
    10.0.0.17   web/1     sshd          22
    10.0.0.17   web/1     sshd          22
    10.0.0.17   web/1     rpcbind       111
    10.0.0.17   web/1     rpcbind       111
    10.0.0.17   web/1     tsa           2222
    10.0.0.17   web/1     atc           8080
    10.0.0.17   web/1     tsa           38283
    10.0.0.17   web/1     tsa           39421
    10.0.0.17   web/1     tsa           40925
    10.0.0.20   worker/1  sshd          22
    10.0.0.20   worker/1  sshd          22
    10.0.0.20   worker/1  rpcbind       111
    10.0.0.20   worker/1  rpcbind       111
    10.0.0.20   worker/1  guardian      7777
    10.0.0.20   worker/1  baggageclaim  7788
    10.0.0.20   worker/1  guardian      17013
    10.0.0.20   worker/1  rpc.statd     33707
