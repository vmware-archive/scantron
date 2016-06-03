module Scantron
  class LsofParser
    def parse(output)
      return nil unless output.include?('COMMAND')

      lines = output.split("\n")
      without_header = lines.drop(1)
      first_line = without_header.first

      first_line.split(' ').first
    end
  end
end
