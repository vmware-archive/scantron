package db

// Update the schema version when the DDL changes
const SchemaVersion = 8

const createDDL = `
CREATE TABLE deployments (
  id integer PRIMARY KEY AUTOINCREMENT,
  name text
);

CREATE TABLE hosts (
  id integer PRIMARY KEY AUTOINCREMENT,
  deployment_id integer,
  name text,
  ip text,
  UNIQUE(ip, name),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
);

CREATE TABLE processes (
  id integer PRIMARY KEY AUTOINCREMENT,
  host_id integer,
  name text,
  pid integer,
  cmdline text,
  user text,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE ports (
  id integer PRIMARY KEY AUTOINCREMENT,
  process_id integer,
  protocol string,
  address string,
  number integer,
  foreignAddress string,
  foreignNumber integer,
  state string,
  FOREIGN KEY(process_id) REFERENCES processes(id)
);

CREATE TABLE tls_informations (
  id integer PRIMARY KEY AUTOINCREMENT,
  port_id integer,
  cert_expiration datetime,
  cert_bits integer,
  cert_country string,
  cert_province string,
  cert_locality string,
  cert_organization string,
  cert_common_name string,
  cipher_suites text,
  mutual bool,
  FOREIGN KEY(port_id) REFERENCES ports(id)
);

CREATE TABLE tls_scan_errors (
  id integer PRIMARY KEY AUTOINCREMENT,
  port_id integer,
  cert_scan_error string,
  FOREIGN KEY(port_id) REFERENCES ports(id)
);

CREATE TABLE env_vars (
  id integer PRIMARY KEY AUTOINCREMENT,
  process_id integer,
  var text,
  FOREIGN KEY(process_id) REFERENCES processes(id)
);

CREATE TABLE files (
  id integer PRIMARY KEY AUTOINCREMENT,
  host_id integer,
  path text,
  permissions integer,
  user text,
  file_group text,
  size integer,
  modified datetime,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE ssh_keys (
  id integer PRIMARY KEY AUTOINCREMENT,
  host_id integer,
  type string,
  key string,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE version (
  version integer
);

CREATE TABLE releases (
  id integer PRIMARY KEY AUTOINCREMENT,
  deployment_id integer,
  name string,
  version string,
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
);

CREATE TABLE regexes (
  id integer PRIMARY KEY AUTOINCREMENT,
  regex string NOT NULL
);

CREATE TABLE file_to_regex (
  file_id integer NOT NULL,
  path_regex_id integer,
  content_regex_id integer NOT NULL,
  FOREIGN KEY(file_id) REFERENCES files(id),
  FOREIGN KEY(path_regex_id) REFERENCES regexes(id),
  FOREIGN KEY(content_regex_id) REFERENCES regexes(id)
);

INSERT INTO version(version) VALUES(?);
`
