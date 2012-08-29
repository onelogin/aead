require 'aead'

require 'macaddr'
require 'pathname'
require 'securerandom'

class AEAD::Nonce
  include Enumerable

  # Number of nonces to reserve between statefile updates
  COUNTER_BATCH_SIZE = 1

  # MAC addresses are 48 octets long
  MAC_ADDRESS_OCTETS = 48 / 8

  # The LSB of the most-significant octet of the MAC is the multicast
  # bit, and should be set on generated MAC addresses to distinguish
  # them from real ones
  MAC_MULTICAST_MASK = 0x010000000000

  # The statefile should not be configurable. All machines should
  # share the same state file.
  STATEFILE = Pathname.new('/var/tmp/ruby-aead').expand_path

  # Packed format of the nonce state. From MSB to LSB:
  #   octets 0 - 8 : fixed (hardware id + random id)
  #   octets 9 - 12: counter
  PACK_FORMAT = "H12 H4 H8"

  # String format of the nonce state.
  STRING_FORMAT = "%012x %04x %08x"

  def initialize
    self.refresh_state! do
      [ self.mac_address, SecureRandom.hex(2), 0.to_s ]
    end
  end

  def each
    loop do
      self.increment_counter!
      yield self.state.pack(PACK_FORMAT)
    end
  end

  protected

  attr_accessor :hardware_id
  attr_accessor :random_id
  attr_accessor :counter
  attr_accessor :counter_limit

  def mac_address
    mac_address_real or mac_address_pseudo
  end

  def refresh_state!
    open_statefile do |io|
      self.state = io.eof? ? yield : io.read.unpack(PACK_FORMAT)

      io.rewind
      io.write self.state(self.counter_limit).pack(PACK_FORMAT)
    end
  end

  def increment_counter!
    self.refresh_state! if (self.counter += 1) >= self.counter_limit
  end

  def state=(state)
    self.hardware_id   = state[0].hex
    self.random_id     = state[1].hex
    self.counter       = state[2].hex
    self.counter_limit = self.counter + COUNTER_BATCH_SIZE
  end

  def state(counter = self.counter)
    (STRING_FORMAT % [ self.hardware_id, self.random_id, counter ]).split(' ')
  end

  private

  def mac_address_real
    Mac.addr.tr(':-', '') rescue nil
  end

  def mac_address_pseudo
    SecureRandom.hex(48 / 8) | MAC_MULTICAST_MASK
  end

  def open_statefile
    STATEFILE.open(File::CREAT | File::RDWR, 0600) do |io|
      begin
        io.flock File::LOCK_EX
        yield io
      ensure
        io.flush
        io.flock File::LOCK_UN
      end
    end
  end
end
