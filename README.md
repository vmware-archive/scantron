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
2. `go get github.com/pivotal-cf/scantron`
3. `cd $GOPATH/src/github.com/pivotal-cf/scantron && glide install`


### SYNOPSIS

    scantron <bosh-scan|direct-scan> [command options]


### COMMAND OPTIONS

    --nmap-results=PATH                        Path to nmap results XML (See GENERATING NMAP RESULTS)

#### BOSH-SCAN

    --director-url=URL                         BOSH Director URL
    --director-username=USERNAME               BOSH Director username
    --director-password=PASSWORD               BOSH Director password
    --bosh-deployment=DEPLOYMENT_NAME          BOSH Deployment

    --gateway-username=USERNAME                BOSH VM gateway username
    --gateway-host=URL                         BOSH VM gateway host
    --gateway-private-key=PATH                 BOSH VM gateway private key

    --uaa-client=OAUTH_CLIENT                  UAA Client
    --uaa-client-secret=OAUTH_CLIENT_SECRET    UAA Client Secret

#### DIRECT-SCAN

    --address=ADDRESS                          Address to scan
    --username=USERNAME                        Username to scan with
    --password=PASSWORD                        Password to scan with
    --private-key=PATH                         Private key to scan with (optional)


### GENERATING NMAP RESULTS

Use nmap to scan 10.0.0.1 through 10.0.0.6, outputting the results as XML:

    nmap -oX results.xml -sV -p - 10.0.0.1-6


### EXAMPLES

    # Direct scanning
    scantron direct-scan --nmap-results results.xml \
      --address scanme.example.com --username ubuntu \
      --password hunter2

    # BOSH
    scantron bosh-scan --nmap-results results.xml \
      --director-url=URL \
      --director-username=USERNAME \
      --director-password=PASSWORD \
      --bosh-deployment=DEPLOYMENT_NAME

    # BOSH with gateway
    scantron bosh-scan --nmap-results results.xml \
      --director-url=URL \
      --director-username=USERNAME \
      --director-password=PASSWORD \
      --bosh-deployment=DEPLOYMENT_NAME \
      --gateway-username=USERNAME \
      --gateway-host=URL \
      --gateway-private-key=PATH

    # BOSH with UAA
    scantron bosh-scan --nmap-results results.xml \
      --director-url=URL \
      --bosh-deployment=DEPLOYMENT_NAME \
      --gateway-username=USERNAME \
      --gateway-host=URL \
      --gateway-private-key=PATH \
      --uaa-client=OAUTH_CLIENT \
      --uaa-client-secret=OAUTH_CLIENT_SECRET


### EXAMPLE OUTPUT

    Host                Job             Service         PID     Port    User    SSL
    10.85.8.91          10.85.8.91      sshd            1184    22      root    ✗
    10.85.8.91          10.85.8.91      rpcbind         566     111     root    ✗
    10.85.8.91          10.85.8.91      ruby            11219   4222    vcap    ✗
    10.85.8.91          10.85.8.91      bosh-agent      834     6868    root    ✓
    10.85.8.91          10.85.8.91      java            11357   8080    vcap    ✗
    10.85.8.91          10.85.8.91      java            11357   8443    vcap    ✓
    10.85.8.91          10.85.8.91      nginx           11421   25250   root    ✗
    10.85.8.91          10.85.8.91      nginx           11427   25250   vcap    ✗
    10.85.8.91          10.85.8.91      nginx           11428   25250   vcap    ✗
    10.85.8.91          10.85.8.91      nginx           11323   25555   root    ✓
    10.85.8.91          10.85.8.91      nginx           11326   25555   vcap    ✓
    10.85.8.91          10.85.8.91      nginx           11327   25555   vcap    ✓
    10.85.8.91          10.85.8.91      rpc.statd       651     57427   statd   ✗
