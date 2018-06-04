Gem::Specification.new do |s|
  s.name          = 'logstash-filter-real_ip'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Evaluates real client IP from X-Forwarded-For header'
  s.description   = 'See https://github.com/fholzer/logstash-filter-real_ip/blob/master/README.md for details.'
  s.homepage      = 'https://github.com/fholzer/logstash-filter-real_ip'
  s.authors       = ['Ferdinand Holzer']
  s.email         = 'ferdinand.holzer@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end
