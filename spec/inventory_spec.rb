require 'scantron/inventory'

RSpec.describe Scantron::Inventory do
  let(:path) { asset_path('inventory.yml') }
  subject(:inventory) { Scantron::Inventory.new(path) }

  it 'lets a user iterate through the hosts' do
    hosts = []

    inventory.each_host do |host|
      hosts << host
    end

    expect(hosts).to eq([
      Scantron::Machine.new('machine-type', 'the-user', 'the-password', '10.0.0.1'),
      Scantron::Machine.new('machine-type', 'the-user', 'the-password', '10.0.0.2'),
      Scantron::Machine.new('machine-type', 'the-user', 'the-password', '10.0.0.3'),
      Scantron::Machine.new('other-machine-type', 'the-other-user', 'the-other-password', '10.0.0.4'),
      Scantron::Machine.new('other-machine-type', 'the-other-user', 'the-other-password', '10.0.0.5'),
      Scantron::Machine.new('other-machine-type', 'the-other-user', 'the-other-password', '10.0.0.6'),
    ])
  end
end
