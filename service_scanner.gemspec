require File.expand_path("../lib/service_scanner/version", __FILE__)

Gem::Specification.new do |gem|
  gem.name    = 'service_scanner'
  gem.version = ServiceScanner::VERSION
  gem.date    = Date.today.to_s

  gem.summary     = "a tool for working out which services are listening on ports"
  gem.description = "there isn't much more to it"

  gem.authors  = ['PCF Security Enablement Team']
  gem.email    = 'pcf-security-enablement@pivotal.io'

  gem.files = Dir['{bin,lib,spec}/**/*', 'README*'] & `git ls-files -z`.split("\0")

  gem.add_dependency('ruby-nmap', '~> 0.8.0')
  gem.add_dependency('net-ssh', '~> 3.1')

  gem.add_development_dependency('rspec', '~> 3.4')
end
