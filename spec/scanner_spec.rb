require 'net/ssh'
require 'nmap/xml'

require 'scantron/lsof_parser'
require 'scantron/rpcinfo_parser'

require 'scantron/scanner'

RSpec.describe Scantron::Scanner do
  let(:lsof_parser) { instance_double(Scantron::LsofParser) }
  let(:rpcinfo_parser) { instance_double(Scantron::RPCInfoParser) }
  let(:results) { instance_double(Nmap::XML) }
  subject(:scanner) { Scantron::Scanner.new(results, lsof_parser, rpcinfo_parser) }

  let(:machine) { Scantron::Machine.new('type', 'username', 'password', 'address') }

  before do
    allow(results).to receive(:hosts).and_return([host])
  end

  context 'when the inventory machine is in the results' do
    let(:host) { instance_double(Nmap::Host, ip: 'address') }
    let(:service1) { instance_double(Nmap::Port, number: 3332) }
    let(:service2) { instance_double(Nmap::Port, number: 2354) }
    let(:app_port) { instance_double(Nmap::Port, number: 60002) }
    let(:rpc_port) { instance_double(Nmap::Port, number: 33673) }
    let(:unknown_port) { instance_double(Nmap::Port, number: 2342) }

    let(:ssh_session) { double }

    before do
      allow(host).to receive(:each_port).and_yield(service1).and_yield(service2).and_yield(app_port).and_yield(rpc_port).and_yield(unknown_port)
      allow(lsof_parser).to receive(:parse).with('service1-output').and_return('service1-name')
      allow(lsof_parser).to receive(:parse).with('service2-output').and_return('service2-name')
      allow(lsof_parser).to receive(:parse).with('app_port-output').and_raise(Scantron::NoServicesListeningOnPort)
      allow(lsof_parser).to receive(:parse).with('rpc_port-output').and_raise(Scantron::NoServicesListeningOnPort)
      allow(lsof_parser).to receive(:parse).with('unknown_port-output').and_raise(Scantron::NoServicesListeningOnPort)

      allow(rpcinfo_parser).to receive(:parse).with('rpcinfo-output', 33673).and_return('rpc-service')
      allow(rpcinfo_parser).to receive(:parse).with('rpcinfo-output', 2342).and_raise(Scantron::NoServicesListeningOnPort)

      expect(Net::SSH).to receive(:start).with('address', 'username', password: 'password').and_yield(ssh_session)

      expect(ssh_session).to receive(:exec!).with('rpcinfo -p').and_return('rpcinfo-output')

      expect(ssh_session).to receive(:exec!).with('echo password | sudo -S -- lsof +c 0 -i :3332').and_return('service1-output')
      expect(ssh_session).to receive(:exec!).with('echo password | sudo -S -- lsof +c 0 -i :2354').and_return('service2-output')
      expect(ssh_session).to receive(:exec!).with('echo password | sudo -S -- lsof +c 0 -i :60002').and_return('app_port-output')
      expect(ssh_session).to receive(:exec!).with('echo password | sudo -S -- lsof +c 0 -i :33673').and_return('rpc_port-output')
      expect(ssh_session).to receive(:exec!).with('echo password | sudo -S -- lsof +c 0 -i :2342').and_return('unknown_port-output')
    end

    it 'scans a machine' do
      results = scanner.scan(machine)

      expect(results).to eq([
        Scantron::Mapping.new(3332, 'service1-name'),
        Scantron::Mapping.new(2354, 'service2-name'),
        Scantron::Mapping.new(60002, 'user application (guessed)'),
        Scantron::Mapping.new(33673, 'rpc-service'),
        Scantron::Mapping.new(2342, '-'),
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
