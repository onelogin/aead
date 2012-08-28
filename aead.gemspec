require 'pathname'

Gem::Specification.new do |gem|
  gem.name    = 'aead'
  gem.version = Pathname.new(__FILE__).join('../VERSION').read.chomp

  gem.author = 'Stephen Touset'
  gem.email  = 'stephen@touset.org'

  gem.homepage    = 'https://github.com/onelogin/aead'
  gem.summary     = %{Ruby library to generate AEADs}
  gem.description = %{Ruby library to generate AEADs}

  gem.bindir      = 'script'
  gem.files       = `git ls-files`            .split("\n")
  gem.executables = `git ls-files -- script/*`.split("\n").map {|e| e[7..-1] }
  gem.test_files  = `git ls-files -- spec/*`  .split("\n")

  gem.add_development_dependency 'bundler'
  gem.add_development_dependency 'cane'
  gem.add_development_dependency 'guard'
  gem.add_development_dependency 'guard-minitest'
  gem.add_development_dependency 'markdown'
  gem.add_development_dependency 'minitest'
  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'redcarpet'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'yard'
  gem.add_development_dependency 'version'
end
