require 'scantron/lsof_parser'

RSpec.describe Scantron::LsofParser do
  subject(:parser) { Scantron::LsofParser.new }

  let(:cc_output) { File.read(asset_path('lsof_cc-uploader.txt')) }
  let(:consul_output) { File.read(asset_path('lsof_consul.txt')) }

  it 'can get the command name which is listening on that port' do
    command = parser.parse(cc_output)
    expect(command).to eq('cc-uploader')
  end

  it 'can get the command name for a different output' do
    command = parser.parse(consul_output)
    expect(command).to eq('consul')
  end

  it 'raises an error if there are no processes listening on that port (empty output)' do
    expect {
      parser.parse('[sudo] password for vcap:')
    }.to raise_error(Scantron::NoServicesListeningOnPort)
  end
end
