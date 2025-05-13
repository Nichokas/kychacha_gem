require 'mkmf'

RUST_DIR = File.expand_path('../', __FILE__)

# Build the Rust library
puts "Building Rust library with cargo..."
Dir.chdir(RUST_DIR) do
  system('cargo build --release') || raise("Failed to build Rust library")
end