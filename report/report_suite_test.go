package report_test

import (
  . "github.com/onsi/ginkgo"
  . "github.com/onsi/gomega"

  "testing"

  "github.com/pivotal-cf/scantron"
  "github.com/pivotal-cf/scantron/db"
  "github.com/pivotal-cf/scantron/scanner"
)

func TestReport(t *testing.T) {
  RegisterFailHandler(Fail)
  RunSpecs(t, "Report Suite")
}

func createTestDatabase(databasePath string) (*db.Database, error) {
  hosts := scanner.ScanResult{
    JobResults: []scanner.JobResult{
      {
        Job: "host3",
        Files: []scantron.File{
          {
            Path:        "/var/vcap/data/jobs/world-readable",
            Permissions: 0004,
          },
          {
            Path:        "/var/vcap/data/jobs/world-writable",
            Permissions: 0002,
          },
          {
            Path:        "/var/vcap/data/jobs/world-executable",
            Permissions: 0001,
          },
        },
        SSHKeys: []scantron.SSHKey{
          {
            Type: "ssh-rsa",
            Key:  "SSH KEY 1",
          },
        },
        Services: []scantron.Process{
          {
            CommandName: "command1",
            User:        "root",
            Ports: []scantron.Port{
              {
                State:   "LISTEN",
                Address: "10.0.5.23",
                Number:  7890,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
                TLSInformation: &scantron.TLSInformation{
                  Certificate: &scantron.Certificate{},
                  CipherInformation: scantron.CipherInformation{
                    "VersionSSL30": []string{"Just the worst"},
                  },
                },
              },
            },
          },
        },
      },
      {
        Job: "host1",
        Files: []scantron.File{
          {
            Path:        "/var/vcap/data/jobs/world-everything",
            Permissions: 0007,
          },
          {
            Path:        "/root/world-everything",
            Permissions: 0007,
          },
        },
        SSHKeys: []scantron.SSHKey{
          {
            Type: "ssh-rsa",
            Key:  "SSH KEY 1",
          },
        },
        Services: []scantron.Process{
          {
            CommandName: "command2",
            User:        "root",
            Ports: []scantron.Port{
              {
                State:   "LISTEN",
                Address: "10.0.5.21",
                Number:  19999,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
              },
            },
          },
          {
            CommandName: "command1",
            User:        "root",
            Ports: []scantron.Port{
              {
                State:   "LISTEN",
                Address: "10.0.5.21",
                Number:  7890,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
                TLSInformation: &scantron.TLSInformation{
                  Certificate: &scantron.Certificate{},
                  CipherInformation: scantron.CipherInformation{
                    "VersionSSL30": []string{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
                  },
                },
              },
              {
                State:   "LISTEN",
                Address: "44.44.44.44",
                Number:  7890,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
              },
              {
                State:   "LISTEN",
                Address: "127.0.0.1",
                Number:  8890,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
                TLSInformation: &scantron.TLSInformation{
                  Certificate: &scantron.Certificate{},
                  CipherInformation: scantron.CipherInformation{
                    "VersionTLS12": []string{"Bad Cipher"},
                  },
                },
              },
              {
                State:  "ESTABLISHED",
                Number: 7891,
                ForeignAddress: "10.0.0.1",
                ForeignNumber: 2345,
              },
            },
          },
          {
            CommandName: "sshd",
            User:        "root",
            Ports: []scantron.Port{
              {
                State:   "LISTEN",
                Address: "10.0.5.21",
                Number:  22,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
              },
            },
          },
          {
            CommandName: "rpcbind",
            User:        "root",
            Ports: []scantron.Port{
              {
                State:   "LISTEN",
                Address: "10.0.5.21",
                Number:  111,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
              },
            },
          },
        },
      },
      {
        Job: "host2",
        SSHKeys: []scantron.SSHKey{
          {
            Type: "ssh-rsa",
            Key:  "SSH KEY 2",
          },
        },
        Services: []scantron.Process{
          {
            CommandName: "command2",
            User:        "root",
            Ports: []scantron.Port{
              {
                State:   "LISTEN",
                Address: "10.0.5.22",
                Number:  19999,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
                TLSInformation: &scantron.TLSInformation{
                  Certificate: &scantron.Certificate{},
                  CipherInformation: scantron.CipherInformation{
                    "VersionTLS12": []string{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
                  },
                },
              },
            },
          },
          {
            CommandName: "some-non-root-process",
            User:        "vcap",
            Ports: []scantron.Port{
              {
                State:   "LISTEN",
                Address: "10.0.5.22",
                Number:  12345,
                ForeignAddress: "0.0.0.0",
                ForeignNumber: -1,
              },
            },
          },
        },
      },
    },
  }

  database, err := db.CreateDatabase(databasePath)
  if err != nil {
    return nil, err
  }

  err = database.SaveReport(hosts)
  if err != nil {
    return nil, err
  }

  return database, nil
}
