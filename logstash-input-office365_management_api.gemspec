Gem::Specification.new do |s|
  s.name          = 'logstash-input-office365_management_api'
  s.version       = '1.0.0'
  s.licenses      = ['GPL-3.0']
  s.summary       = 'Pulls logs/events from the Office 365 Management Activity API'
  s.description   = 'This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program'
  s.homepage      = 'https://www.github.com/dunbarcyber/logstash-input-o365'
  s.authors       = ['Tom Callahan']
  s.email         = 'tom.callahan@dunbarsecured.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_runtime_dependency 'logstash-codec-json'
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'stud', '>= 0.0.22'
  s.add_runtime_dependency 'adal'
  s.add_development_dependency 'logstash-devutils', '>= 0.0.16'
end
