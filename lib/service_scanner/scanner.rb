require "net/ssh"
require "nmap/xml"

module ServiceScanner
  class UnknownMachine < StandardError; end

  Mapping = Struct.new(:port, :service)

  class Scanner
    def initialize(results, parser)
      @results = results
      @parser = parser
    end

    def scan(machine)
      host = results.hosts.find { |h| h.ip == machine.address }

      raise UnknownMachine unless host

      results = []

      Net::SSH.start(machine.address, machine.username, password: machine.password) do |ssh|
        host.each_port do |port|
          output = ssh.exec!("echo #{machine.password} | sudo -S -- lsof +c 0 -i :#{port.number}")

          begin
            service = parser.parse(output)
          rescue ServiceScanner::NoServicesListeningOnPort
            service = "-"
          end

          results << Mapping.new(port.number, service)
        end
      end

      results
    end

    private

    attr_reader :results, :parser
  end
end
