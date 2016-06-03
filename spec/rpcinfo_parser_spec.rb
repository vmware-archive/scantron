require 'scantron/rpcinfo_parser'

RSpec.describe Scantron::RPCInfoParser do
  subject(:parser) { Scantron::RPCInfoParser.new }

  let(:output) { File.read(asset_path('rpcinfo.txt')) }

  it 'can get the command name which is listening on a port' do
    command = parser.parse(output, 33644)
    expect(command).to eq('nlockmgr')
  end

  it 'can get the command name for a different output' do
    command = parser.parse(output, 111)
    expect(command).to eq('portmapper')
  end

  it 'raises an error if there are no processes listening on that port (empty output)' do
    expect {
      parser.parse(output, 1337)
    }.to raise_error(Scantron::NoServicesListeningOnPort)
  end
end
