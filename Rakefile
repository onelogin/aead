require 'rake/testtask'
require 'rake/version_task'
require 'cane/rake_task'
require 'yard'

task :default => %w{ test cane }

Rake::TestTask.new do |t|
  t.libs.push 'lib'
  t.libs.push 'spec'

  t.test_files = FileList['spec/**/*_spec.rb']
  t.verbose    = true
end

Cane::RakeTask.new

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
