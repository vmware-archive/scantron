require 'service_scanner/inventory'

RSpec.describe ServiceScanner::Inventory do
  let(:path) { asset_path('inventory.yml') }
  subject(:inventory) { ServiceScanner::Inventory.new(path) }

  it 'lets a user iterate through the hosts' do
    hosts = []

    inventory.each_host do |host|
      hosts << host
    end

    expect(hosts).to eq([
      ServiceScanner::Machine.new('machine-type', 'the-user', 'the-password', '10.0.0.1'),
      ServiceScanner::Machine.new('machine-type', 'the-user', 'the-password', '10.0.0.2'),
      ServiceScanner::Machine.new('machine-type', 'the-user', 'the-password', '10.0.0.3'),
      ServiceScanner::Machine.new('other-machine-type', 'the-other-user', 'the-other-password', '10.0.0.4'),
      ServiceScanner::Machine.new('other-machine-type', 'the-other-user', 'the-other-password', '10.0.0.5'),
      ServiceScanner::Machine.new('other-machine-type', 'the-other-user', 'the-other-password', '10.0.0.6'),
    ])
  end
end
