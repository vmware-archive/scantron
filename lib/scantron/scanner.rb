require "net/ssh"
require "nmap/xml"

require 'scantron/mapping'

module Scantron
  class UnknownMachine < StandardError; end

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

          service = guess_service(port.number, output)

          results << Mapping.new(port.number, service)
        end
      end

      results
    end

    private

    def guess_service(port_number, output)
      begin
        parser.parse(output)
      rescue Scantron::NoServicesListeningOnPort
        if port_number > 60000
          'user application (guessed)'
        else
          '-'
        end
      end
    end

    attr_reader :results, :parser
  end
end
