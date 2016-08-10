module Scantron
  Mapping = Struct.new(:port, :service, :ssl) do
    def ssl?
      ssl
    end
  end
end
