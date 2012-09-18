require 'rake/testtask'
require 'rake/version_task'
require 'yard'

task :default => %w{ build test }

task :build do
  Dir.chdir('ext/openssl/cipher/aead') do
    system %{ruby extconf.rb}
    system %{make}
    system %{cp aead.#{RbConfig::CONFIG['DLEXT']} ../../../../lib/openssl/cipher}
  end
end

Rake::TestTask.new do |t|
  t.libs.push 'lib'
  t.libs.push 'spec'

  t.test_files = FileList['spec/**/*_spec.rb']
  t.verbose    = true
end

if defined?(RUBY_ENGINE) and RUBY_ENGINE == 'ruby'
  require 'cane/rake_task'

  task :default => :cane

  Cane::RakeTask.new do |t|
    t.add_threshold 'coverage/coverage.txt', :>=, 100
  end
end

Rake::VersionTask.new do |t|
  t.with_git_tag = true
end

YARD::Rake::YardocTask.new(:doc) do |t|
  # --no-stats applies only to the `yard stats` command, so to include
  # it we have to disable automatic stat generation and do it
  # ourselves
  t.options << '--no-stats'
  t.after = lambda do
    stats = YARD::CLI::Stats.new
    stats.run '--list-undoc'
  end
end
