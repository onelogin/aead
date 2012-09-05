require 'aead'

require 'macaddr'
require 'pathname'
require 'securerandom'

class AEAD::Nonce
  # Number of octets in the counter field.
  COUNTER_OCTET_SIZE = 4

  # Initial value of the counter field (4 octets zeroed out)
  COUNTER_INITIAL_VALUE = '%08x' % 0

  # Maximum possible value of the counter before rolling over (4
  # octets all set to one).
  COUNTER_MAXIMUM_VALUE = '%08x' % (2 ** (COUNTER_OCTET_SIZE * 8) - 1)

  # Number of nonces to reserve between state file updates. 256 is
  # convenient in that it leads to pleasant state files and represents
  # a reasonable medium between frequent file locks and wasted
  # nonce values when the process terminates.
  COUNTER_BATCH_SIZE = 0xff

  # The LSB of the most-significant octet of the MAC is the multicast
  # bit, and should be set on generated MAC addresses to distinguish
  # them from real ones
  MAC_MULTICAST_MASK = 0x010000000000

  # The statefile is not configurable. All processes on a single
  # machine must share the same state file.
  STATE_FILE = Pathname.new('/var/tmp/ruby-aead').expand_path

  # Packed format of the nonce state. As recommended by RFC 5116. From
  # MSB to LSB:
  #   octets 1 - 8 : fixed (hardware id + random id)
  #   octets 9 - 12: counter
  PACK_FORMAT = "H12 H4 H8"

  def initialize
    self.state_file = STATE_FILE
  end

  def initialize_copy(other)
    @_state = nil
  end

  def shift(count = nil)
    return self.state.pack(PACK_FORMAT) if count.nil?

    count.times.map do
      self.state.pack(PACK_FORMAT)
    end
  end

  protected

  attr_accessor :state_file

  def state
    @_state ||= load_state
    @_state[0..2]
  ensure
    raise if $!

    @_state = bump_state(@_state.dup)
    @_state = load_state if (@_state[2].hex > @_state[3].hex)
  end

  private

  #
  # Returns the initial state value:
  #  * Octets 1 -  6: MAC address
  #  * Octets 7 -  8: Random identifier
  #  * Octets 9 - 12: Zeroed out counter
  #
  def init_state
    [ mac_address, SecureRandom.hex(2), COUNTER_INITIAL_VALUE ]
  end

  #
  # Loads the state from the state file, reserving
  # `COUNTER_BATCH_SIZE` nonces in the state file between
  # invocations.
  #
  def load_state
    open_state_file do |io|
      bytes    = io.read
      state    =
        bytes.bytesize == 12 ? bump_state(bytes.unpack(PACK_FORMAT)) :
        bytes.bytesize ==  0 ? init_state                            :
        nil

      raise SecurityError,
        "nonce state file corrupt, MANUAL REPAIR REQUIRED, DO NOT RM" unless
          state

      raise SecurityError,
        "nonce state file must not be copied from another machine" unless
          mac_addresses_real.include?(state.first) or
          state.first.hex & MAC_MULTICAST_MASK != 0

      state[3] = bump_counter(state[2], COUNTER_BATCH_SIZE)
      output   = (state[0..1] << state[3]).pack(PACK_FORMAT)

      io.rewind
      io.write output

      state
    end
  end

  def bump_state(state)
    raise SecurityError, "nonce counter has reached maximum value" if
      COUNTER_MAXIMUM_VALUE.hex < state[2].hex

    state[2] = bump_counter state[2], 1
    state
  end

  def bump_counter(counter, increment)
    "%08x" % (counter.hex + increment)
  end

 private

  def open_state_file
    self.state_file.open(File::CREAT | File::RDWR, 0600) do |io|
      begin
        io.flock File::LOCK_EX
        yield io
      ensure
        io.flush
        io.flock File::LOCK_UN
      end
    end
  end

  def mac_address
    mac_address_real or mac_address_pseudo
  end

  def mac_address_real
    mac_addresses_real.first
  end

  def mac_addresses_real
    Mac.addr.list.map {|addr| addr.tr(':-', '') } rescue []
  end

  def mac_address_pseudo
    (SecureRandom.hex(48 / 8).hex | MAC_MULTICAST_MASK).to_s(16)
  end
end
