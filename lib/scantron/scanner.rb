require "net/ssh"
require "nmap/xml"

require 'scantron/mapping'

module Scantron
  class UnknownMachine < StandardError; end

  class Scanner
    def initialize(results, lsof_parser, rpcinfo_parser)
      @results = results
      @lsof_parser = lsof_parser
      @rpcinfo_parser = rpcinfo_parser
    end

    def scan(machine)
      host = results.hosts.find { |h| h.ip == machine.address }

      raise UnknownMachine unless host

      results = []

      Net::SSH.start(machine.address, machine.username, password: machine.password) do |ssh|
        rpcinfo_output = ssh.exec!("rpcinfo -p")

        host.each_port do |port|
          lsof_output = ssh.exec!("echo #{machine.password} | sudo -S -- lsof +c 0 -i :#{port.number}")

          service = guess_service(port.number, lsof_output, rpcinfo_output)

          results << Mapping.new(port.number, service)
        end
      end

      results
    end

    private

    def guess_service(port_number, lsof_output, rpcinfo_output)
      service = lsof_parser.parse(lsof_output)
      return service if service

      return 'cloud foundry app' if port_number > 60000

      service = rpcinfo_parser.parse(rpcinfo_output, port_number)
      return service if service

      '-'
    end

    attr_reader :results, :lsof_parser, :rpcinfo_parser
  end
end
