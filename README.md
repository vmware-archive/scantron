# Scantron

> scan machines for unexpected processes, ports, or permissions

## Purpose

Scantron is a tool for performing a census of processes, ports, protocols, and
file permissions on VMs. Scans can be performed against single VMs, or against
all VMs in a bosh deployment. The intention is to provide a point-in-time scan
which can be analysed offline. Scans are stored in a SQLite database. The CLI
provides a summary report format or the SQLite db can be queried directly.

## Usage

Whether you scan a single host (`direct-scan`) or all VMs in a bosh deployment
(`bosh-scan`) the results of the scan will be stored in a SQLite file, or
appended to an existing file.

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
      
Multiple deployments can be specified and the results merged into a single database.

    scantron bosh-scan \
      --director-url <bosh address> \
      --bosh-deployment <bosh deployment name> \
      --bosh-deployment <second bosh deployment name> \
      --client scantron \
      --client-secret <scantron secret> \
      [--ca-cert bosh.pem]

**Note:** The scan expects to be able to reach the BOSH machines directly at
the moment so that it can scan the endpoints for their TLS configuration. A
jumpbox is normally a good machine to run this from.

#### File Content Check

The file scan can optionally flag files if the content matches a specified regex. For performance optimization 
an optional path regex and maximum file size can be specified to limit which files have to be read. The maximum 
file size defaults to 1MB.

    scantron bosh-scan|direct-scan \
      --content <content regex> \
      [--path <file path regex>] \
      [--max <file size in bytes>]
      
Regexes use the [golang syntax](https://golang.org/pkg/regexp/syntax/).

### Checking Reports

After you run a scan a report is saved to a SQLite database, by default
`database.db`.

With this report it is possible to do the following:

* Generate a summary of the findings.

        scantron report

  The report has sections for:
  * Externally-accessible processes running as root
    * Excluding sshd and rpcbind
  * Processes using non-approved SSL/TLS settings 
    * Current recommendation is TLS 1.2 and ciphers recommended by 
      https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
  * World-readable files
    * Filtered for files from bosh releases (/var/vcap/data/jobs/%)
  * Duplicate SSH keys

* Check to see if any unexpected processes or ports are present in your
  cluster.

        scantron audit --manifest manifest-of-expected-things.yml

The output from `audit` lists the audited host(s) along with either `err` or
`ok`.  Where there are discrepancies with the manifest are highlighted. If
there are any discrepancies the exit code will be `3`, otherwise it is `0`.

* Generate a manifest (preliminary) of "known good" ports and processes. 

         scantron generate-manifest > manifest.yml

**Note:** Some hand-tweaking may be necessary if there are non-deterministic
ports in your cluster as the generated manifest will contain exactly those
found in the latest scan.

## Notes

### Scan Filter

Scantron only scans regular files and skips the following directories:

  * `/proc`
  * `/sys`
  * `/dev`
  * `/run`

### Database Schema

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

### Queries

To analyze the results of the database, you can use the database schema documented
above to craft your own SQL query, or use some of the example queries stored in the
`example_queries` directory.

* Finding all of the hosts which are listening on a particular port:
  - hosts_on_port.sql
* Finding all connections not using TLS:
  - no_tls.sql
* Finding all processes running as `root`
  - root_processes.sql

Once you have your query, run `sqlite` and specify the query you want to run to generate
results. Tip: You can include `.mode.csv` at the end of your argument to spit out the results
in a CSV format that can be imported into the spreadsheet software of your choice.

### Manifest Format

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

## Development

### Building

1. Install dep, the vendor package manager: https://github.com/golang/dep
2. `go get github.com/pivotal-cf/scantron`
3. `cd $GOPATH/src/github.com/pivotal-cf/scantron`
4. `dep ensure` # Note: will fail with exit code 1 due to `doublestar` test files 
5. `./scripts/build`

### Testing

1. `./scripts/test`
2. There is no step 2.
