require_relative "kychacha_gem/version"
require 'ffi'

module KychachaGem
  class Error < StandardError; end

  class FFIBindings
    extend FFI::Library
    # Load rust library
    ffi_lib File.expand_path("../target/release/librs_kychacha_gem.#{FFI::Platform::LIBSUFFIX}", __dir__)

    # Declare extern functions
    attach_function :generate_keypair, [], :pointer
    attach_function :get_priv_key, [:pointer], :pointer
    attach_function :get_pub_key, [:pointer], :pointer
    attach_function :encrypt, [:string, :string], :pointer
    attach_function :decrypt, [:string, :string], :pointer
    attach_function :free_string, [:pointer], :void

    private_class_method :new
  end

  # Create a custom memory pointer with automatic cleanup
  class ManagedPointer < FFI::AutoPointer
    def self.release(pointer)
      FFIBindings.free_string(pointer) unless pointer.null?
    end

    def to_s
      return "" if self.null?
      self.read_string.force_encoding("UTF-8")
    end
  end

  class KeyPair
    def initialize(pointer)
      @pointer = ManagedPointer.new(pointer)
    end

    def to_s
      @pointer.to_s
    end

    def private_key
      ptr = FFIBindings.get_priv_key(@pointer)
      ManagedPointer.new(ptr)
    end

    def public_key
      ptr = FFIBindings.get_pub_key(@pointer)
      ManagedPointer.new(ptr)
    end
  end

  def self.generate_keypair
    ptr = FFIBindings.generate_keypair
    KeyPair.new(ptr)
  end

  def self.encrypt(public_key, message)
    key_str = public_key.to_s
    msg_str = message.to_s
    ptr = FFIBindings.encrypt(key_str, msg_str)
    ManagedPointer.new(ptr)
  end

  def self.decrypt(private_key, encrypted_data)
    key_str = private_key.to_s
    enc_str = encrypted_data.to_s
    ptr = FFIBindings.decrypt(key_str, enc_str)
    ManagedPointer.new(ptr)
  end
end