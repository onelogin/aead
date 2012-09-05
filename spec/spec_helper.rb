require 'simplecov'

SimpleCov.start do
  command_name 'MiniTest'
  add_filter   '/.bundle/'
  add_filter   '/spec/'
  add_filter   '/vendor/'
end unless defined?(RUBY_ENGINE) and RUBY_ENGINE == 'rbx'

require 'minitest/autorun'
require 'minitest/pride'
require 'minitest/spec'

$LOAD_PATH << File.expand_path('../../lib',  __FILE__)
$LOAD_PATH << File.expand_path('../../test', __FILE__)
