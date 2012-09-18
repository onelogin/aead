require 'simplecov'

unless defined?(RUBY_ENGINE) and RUBY_ENGINE == 'rbx'
  SimpleCov.start do
    command_name 'MiniTest'
    add_filter   '/spec/'
    add_filter   '/vendor/'
  end

  SimpleCov.at_exit do
    path = Pathname.new('coverage/coverage.txt')
    path.dirname.mkpath
    path.open('w') do |io|
      io << SimpleCov.result.source_files.covered_percent
    end
  end
end

require 'minitest/autorun'
require 'minitest/pride'
require 'minitest/spec'
require 'minitest/benchmark'

$LOAD_PATH << File.expand_path('../../lib',  __FILE__)
