require 'spec_helper'

require 'aead/nonce'
require 'tempfile'
require 'set'

describe AEAD::Nonce do
  subject { AEAD::Nonce.new }

  before do
    subject.send(:state_file=, self.state_file)
  end

  after do
    subject.send(:state_file).unlink
  end

  let(:temp_file) do
    Tempfile.new('ruby-aead')
  end

  let(:state_file) do
    Pathname.new(self.temp_file.path)
  end

  it 'must create nonexistent state files with restrictive permissions' do
    self.state_file.unlink

    subject.shift

    self.state_file          .must_be :exist?
    self.state_file.stat.mode.must_equal 0100600
    self.state_file.size     .must_equal 12
  end

  it 'must generate 12-byte nonces' do
    subject.shift.bytesize.must_equal 12
  end

  it 'must generate sequential nonces' do
    subject.shift.must_be :<, subject.shift
  end

  it 'must never generate duplicate nonces across multiple instances' do
    subject.shift # ensure state is initialized

    copy  = subject.clone
    count = subject.class::COUNTER_BATCH_SIZE * 10

    t_1 = Thread.new { Set.new.tap {|s| count.times { s << subject.shift } } }
    t_2 = Thread.new { Set.new.tap {|s| count.times { s << copy   .shift } } }

    (t_1.value + t_2.value).length.must_equal(count * 2)
  end

  it 'must be thread-safe' do
    count   = subject.class::COUNTER_BATCH_SIZE * 5
    thread  = -> { Set.new.tap {|s| count.times { s << subject.shift } } }
    threads = 5.times.map { Thread.new(&thread) }

    threads.map(&:value).inject(&:+).length.must_equal(count * 5)
  end

  it 'must not allow the counter to roll over' do
    self.state_file.open('w') do |io|
      io.write [
        '1' * 12,
        '0' *  4,
        '%08x' % (subject.class::COUNTER_MAXIMUM_VALUE.hex - 5),
      ].pack(subject.class::PACK_FORMAT)
    end

    subject.shift(5)

    -> { subject.shift }.must_raise ArgumentError
  end

  it 'must reserve chunks of nonces in the state file' do
    subject.shift # prime the state_file

    self.state_file.open('rb') do |io|
      io.read.must_equal subject.shift(subject.class::COUNTER_BATCH_SIZE).last
      io.rewind

      subject.shift

      io.read.must_equal subject.shift(subject.class::COUNTER_BATCH_SIZE).last
    end
  end

  it 'must abort when the nonce state file can be determined to be corrupt' do
    [1, 11, 13, 500].each do |count|
      self.state_file.open('w') do |io|
        io.write SecureRandom.random_bytes(count)
      end

      -> { subject.shift }.must_raise ArgumentError
    end
  end

  it 'must abort when the nonce contains the MAC for a different machine' do
    self.state_file.open('w') do |io|
      io.write [
        # FIXME: use ~MAC_MULTICAST_MASK, but figure out how to do so
        # reliably given Ruby's inability to do binary math correctly :(
        (SecureRandom.hex(6).hex & 0x101111111111).to_s(16),
        SecureRandom.hex(2),
        SecureRandom.hex(4),
      ].pack(subject.class::PACK_FORMAT)
    end

    -> { subject.shift }.must_raise ArgumentError
  end

  it 'must not abort when the nonce contains a pseudo MAC address' do
    subject.stub(:mac_address, subject.send(:mac_address_pseudo)) do
      subject.shift.must_be_kind_of String
    end
  end
end
