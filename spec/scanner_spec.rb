require "net/ssh"
require "nmap/xml"
require "scantron/lsof_parser"

require 'scantron/scanner'

RSpec.describe Scantron::Scanner do
  let(:parser) { instance_double(Scantron::LsofParser) }
  let(:results) { instance_double(Nmap::XML) }
  subject(:scanner) { Scantron::Scanner.new(results, parser) }

  let(:machine) { Scantron::Machine.new('type', 'username', 'password', 'address') }

  before do
    allow(results).to receive(:hosts).and_return([host])
  end

  context 'when the inventory machine is in the results' do
    let(:host) { instance_double(Nmap::Host, ip: 'address') }
    let(:port1) { instance_double(Nmap::Port, number: 3332) }
    let(:port2) { instance_double(Nmap::Port, number: 2354) }
    let(:ssh_session) { double }

    it 'scans a machine' do
      allow(host).to receive(:each_port).and_yield(port1).and_yield(port2)
      allow(parser).to receive(:parse).with('output').and_return('service-name')

      expect(Net::SSH).to receive(:start).with('address', 'username', password: 'password').and_yield(ssh_session)

      expect(ssh_session).to receive(:exec!).with('echo password | sudo -S -- lsof +c 0 -i :3332').and_return('output')
      expect(ssh_session).to receive(:exec!).with('echo password | sudo -S -- lsof +c 0 -i :2354').and_return('output')

      results = scanner.scan(machine)

      expect(results).to eq([
        Scantron::Mapping.new(3332, 'service-name'),
        Scantron::Mapping.new(2354, 'service-name'),
      ])
    end
  end

  context 'when the inventory machine is not in the results' do
    let(:host) { double(Nmap::Host, ip: 'different-address') }

    it 'raises an exception' do
      expect {
        scanner.scan(machine)
      }.to raise_error(Scantron::UnknownMachine)
    end
  end
end
