require File.expand_path("../lib/scantron/version", __FILE__)

Gem::Specification.new do |gem|
  gem.name    = 'scantron'
  gem.version = Scantron::VERSION
  gem.date    = Date.today.to_s

  gem.summary     = "a tool for working out which services are listening on ports"
  gem.description = "there isn't much more to it"

  gem.authors  = ['PCF Security Enablement Team']
  gem.email    = 'pcf-security-enablement@pivotal.io'

  gem.files = Dir['{bin,lib,spec}/**/*', 'README*'] & `git ls-files -z`.split("\0")

  gem.add_dependency('ruby-nmap', '~> 0.8.0')
  gem.add_dependency('net-ssh', '~> 3.2')

  gem.add_development_dependency('rspec', '~> 3.4')
end
