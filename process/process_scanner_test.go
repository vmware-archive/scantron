package process_test

import (
  "fmt"
  "github.com/golang/mock/gomock"
  . "github.com/onsi/ginkgo"
  . "github.com/onsi/gomega"
  . "github.com/onsi/gomega/gstruct"
  "github.com/pivotal-cf/scantron"
  "github.com/pivotal-cf/scantron/process"
  "github.com/pivotal-cf/scantron/scanlog"
  "github.com/pivotal-cf/scantron/tlsscan"
  "time"
)

var _ = Describe("ProcessScanner", func() {

  var (
    mockCtrl            *gomock.Controller
    mockSystemResources *process.MockSystemResources
    mockTlsScanner      *tlsscan.MockTlsScanner
    subject             *process.ProcessScanner
  )

  BeforeEach(func() {
    mockCtrl = gomock.NewController(GinkgoT())
    mockSystemResources = process.NewMockSystemResources(mockCtrl)
    mockTlsScanner = tlsscan.NewMockTlsScanner(mockCtrl)
    subject = &process.ProcessScanner{
      SysRes: mockSystemResources,
      TlsScan: mockTlsScanner,
    }
  })

  AfterEach(func() {
    mockCtrl.Finish()
  })

  It("Should associate ports with processes", func() {

    systemProcesses := []scantron.Process{
      {
        CommandName: "command",
        PID:         123,
        User:        "user",
        Cmdline:     []string{"cmd", "arg"},
        Env:         []string{"foo=bar"},
      },
    }

    port := scantron.Port{
      Protocol:       "tcp",
      Address:        "1.2.3.4",
      Number:         4567,
      ForeignAddress: "2.3.4.5",
      ForeignNumber:  6789,
      State:          "Established",
    }
    systemPorts := []process.ProcessPort{
      {
        PID:  123,
        Port: port,
      },
    }

    portIdFn := func(element interface{}) string {
     return fmt.Sprintf("%d", element.(scantron.Port).Number)
    }

    mockSystemResources.EXPECT().GetProcesses().Return(systemProcesses, nil).Times(1)
    mockSystemResources.EXPECT().GetPorts().Return(systemPorts).Times(1)

    processes, err := subject.ScanProcesses(scanlog.NewNopLogger())

    Expect(err).Should(BeNil())
    Expect(processes).Should(HaveLen(1))
    Expect(processes[0]).Should(MatchAllFields(Fields{
      "CommandName": Equal("command"),
      "PID":         Equal(123),
      "User":        Equal("user"),
      "Cmdline":     Equal([]string{"cmd", "arg"}),
      "Env":         Equal([]string{"foo=bar"}),
      "Ports": MatchAllElements(portIdFn, Elements{
       "4567": MatchAllFields(Fields{
         "Protocol":       Equal("tcp"),
         "Address":        Equal("1.2.3.4"),
         "Number":         Equal(4567),
         "ForeignAddress": Equal("2.3.4.5"),
         "ForeignNumber":  Equal(6789),
         "State":          Equal("Established"),
         "TLSInformation": BeNil(),
       }),
      }),
    }))
  })

  It("Should scan TLS ciphers for listening TCP ports", func() {

    systemProcesses := []scantron.Process{
      {
        CommandName: "command",
        PID:         123,
        User:        "user",
        Cmdline:     []string{"cmd", "arg"},
        Env:         []string{"foo=bar"},
      },
    }

    port := scantron.Port{
      Protocol:       "tcp",
      Address:        "1.2.3.4",
      Number:         4567,
      ForeignAddress: "0.0.0.0",
      ForeignNumber:  -1,
      State:          "Listen",
    }
    systemPorts := []process.ProcessPort{
      {
        PID:  123,
        Port: port,
      },
    }

    portIdFn := func(element interface{}) string {
      return fmt.Sprintf("%d", element.(scantron.Port).Number)
    }

    mockSystemResources.EXPECT().GetProcesses().Return(systemProcesses, nil).Times(1)
    mockSystemResources.EXPECT().GetPorts().Return(systemPorts).Times(1)

    cipherInformation := scantron.CipherInformation{
      "VersionSSL30": []string{"cipher"},
    }
    mockTlsScanner.EXPECT().Scan(gomock.Any(), gomock.Eq("localhost"), gomock.Eq("4567")).Return(cipherInformation, nil).Times(1)

    certificate := &scantron.Certificate{
      Expiration: time.Time{},
      Bits:       2048,
      Subject: scantron.CertificateSubject{
        Country:  "",
        Province: "",
        Locality: "",

        Organization: "",
        CommonName:   "",
      },
    }
    mockTlsScanner.EXPECT().FetchTLSInformation("localhost", "4567").Return(
      certificate, false, nil).Times(1)

    processes, err := subject.ScanProcesses(scanlog.NewNopLogger())

    Expect(err).Should(BeNil())
    Expect(processes).Should(HaveLen(1))
    Expect(processes[0]).Should(MatchAllFields(Fields{
      "CommandName": Equal("command"),
      "PID":         Equal(123),
      "User":        Equal("user"),
      "Cmdline":     Equal([]string{"cmd", "arg"}),
      "Env":         Equal([]string{"foo=bar"}),
      "Ports": MatchAllElements(portIdFn, Elements{
        "4567": MatchAllFields(Fields{
          "Protocol":       Equal("tcp"),
          "Address":        Equal("1.2.3.4"),
          "Number":         Equal(4567),
          "ForeignAddress": Equal("0.0.0.0"),
          "ForeignNumber":  Equal(-1),
          "State":          Equal("Listen"),
          "TLSInformation": PointTo(MatchAllFields(Fields{
            "Certificate": Equal(certificate),
            "CipherInformation":Equal(cipherInformation),
            "Mutual": BeFalse(),
            "ScanError": BeNil(),
          })),
        }),
      }),
    }))
  })
})