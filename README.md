# scantron

> scan BOSH deployments for security vulnerabilities

## usage

### scanning machines

#### single host scan

You can perform a direct scan (a scan of a single host) by using the following
command:

    scantron direct-scan \
      --address scanme.example.com
      --username ubuntu \
      --password hunter2 \
      [--private-key ~/.ssh/id_rsa_scantron]

The password is always required because we use it to `sudo` on the machine for
the scan. You may optionally pass a private key for authenticating SSH.

#### bosh deployment scan

Scantron is typically used in CI jobs and by other machines and so only
supports authenticating with client credentials with a BOSH director at the
moment. You can create a client for use with Scantron like so:

1. `uaac target <bosh uaa host>:<bosh uaa port>`
2. `uaac token owner get login admin`
3. `uaac client add scantron -s <scantron secret> --authorized_grant_types client_credentials --scope bosh.admin --authorities bosh.admin --access_token_validity 600 --refresh_token_validity 86400`

You can then scan a BOSH deployment with the following command:

    scantron bosh-scan \
      --director-url <bosh address> \
      --bosh-deployment <bosh deployment name> \
      --client scantron \
      --client-secret <scantron secret> \
      [--ca-cert bosh.pem]

**Note:** The scan expects to be able to reach the BOSH machines directly at
the moment so that it can scan the endpoints for their TLS configuration. A
jumpbox is normally a good machine to run this from.

### checking reports

After you have generated the report you can check it for compliance (no
unexpected hosts or ports) against a known good manifest. These manifests can
be quite lengthy! There is a `scantron` subcommand you can run in order to
initially generate one.

     scantron generate-manifest > bosh.yml

Some hand-tweaking may be necessary to handle non-deterministic ports in the
generated manifest file. The resulting manifest file can be checked against a
report.

     scantron audit --manifest bosh.yml

Audit outputs the audited hosts along with either `err` or `ok`. When there's
any error, audit highlights the mismatched processes, ports, and/or permissions
and returns with exit code 3. If audit does not have any errors, it will return
with exit code 0.

## notes

### scan filter

Scantron only scans regular files and skips the following directories:

  * `/proc`
  * `/sys`
  * `/dev`
  * `/run`

### database schema

Scantron produces a SQLite database for scan reports. The database schema can
be found in [schema.go](https://github.com/pivotal-cf/scantron/blob/master/db/schema.go).

Scantron does not currently support database migrations. You will be prompted
to create a new database when there are backwards-incompatible changes to the
schema.

Each scan creates a report with many hosts in it. Hosts represent scanned VMs
which contain the list of world writable files and processes running on that
machine. Each process is referenced by the port it is listening on and its
environment variables. TLS information is provided for a port when the port is
expecting TLS connections.

### example queries

Finding all of the hosts which are listening on a particular port:

``` sql
SELECT hosts.NAME
FROM ports
  JOIN processes
    ON ports.process_id = processes.id
  JOIN hosts
    ON processes.host_id = hosts.id
WHERE ports.number = 6061
  AND ports.state = "listen"
```

### manifest format

Scantron audits the hosts, processes, and ports in the database against the
user-generated manifest file.

For Ops Manager where VMs can have the same prefix, such as cloud_controller
and cloud_controller_worker, append "-" to the prefixes: "cloud_controller-"
and "cloud_controller_worker-".

Many hosts (especially those which are based of the BOSH stemcell) will start
processes that bind to an ephemeral, random port when they start. To avoid
caring about these ports when we perform an audit you can add `ignore_ports:
true` to the process. There is an example of this below for the `rpc.statd`
process.

This is an example of the manifest file:

``` yaml
specs:
- prefix: cloud_controller-
  processes:
  - command: sshd
    user: root
    ports:
    - 22
  - command: rpcbind
    user: root
    ports:
    - 111
  - command: metron
    user: vcap
    ports:
    - 6061
  - command: consul
    user: vcap
    ports:
    - 8301
  - command: nginx
    user: root
    ports:
    - 9022
  - command: ruby
    user: vcap
    ports:
    - 33861
  - command: rpc.statd
    user: root
    ignore_ports: true
```

## development

### building

1. Install dep, the vendor package manager: https://github.com/golang/dep
2. `go get github.com/pivotal-cf/scantron`
3. `cd $GOPATH/src/github.com/pivotal-cf/scantron && dep ensure`
4. `./scripts/build`

### testing

1. `./scripts/test`
2. There is no step 2.
