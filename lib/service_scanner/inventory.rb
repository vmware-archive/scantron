require 'yaml'

module ServiceScanner
  Machine = Struct.new(:type, :username, :password, :address)

  class Inventory
    def initialize(path)
      @path = path
    end

    def each_host(&blk)
      hosts = YAML.load_file(path).fetch('hosts')

      hosts.each do |host|
        addresses = host.fetch('addresses')

        addresses.each do |address|
          machine = ServiceScanner::Machine.new(
            host.fetch('name'),
            host.fetch('username'),
            host.fetch('password'),
            address
          )

          yield machine
        end
      end
    end

    private

    attr_reader :path
  end
end
