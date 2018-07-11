GEM=logstash-filter-real_ip

build: $(GEM).zip

%.zip: %.gem
	GNAME="$(GEM)-$$(ruby -e 'require "rubygems";spec = Gem::Specification::load("$(GEM).gemspec");puts spec.version;')" && \
	zip "$$GNAME.zip" "$$GNAME.gem"

%.gem:
	gem build $(GEM).gemspec
