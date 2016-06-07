module Scantron
  class LsofParser
    def parse(output)
      return nil unless output.include?('COMMAND')

      lines = output.split("\n")
      without_header = lines.drop(1)
      listening = without_header.find { |l| l.include? "LISTEN" }

      listening.split(' ').first
    end
  end
end
