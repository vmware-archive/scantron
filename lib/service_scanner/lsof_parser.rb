module ServiceScanner
  class NoServicesListeningOnPort < StandardError; end

  class LsofParser
    def parse(output)
      raise NoServicesListeningOnPort unless output.include?('COMMAND')

      lines = output.split("\n")
      without_header = lines.drop(1)
      first_line = without_header.first

      first_line.split(' ').first
    end
  end
end
