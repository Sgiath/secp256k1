# Usage Guide

This guide covers the basic usage of the `lib_secp256k1` library for Elixir.

## Installation

### System Dependencies

The library requires a C compiler and standard build tools to compile the underlying `secp256k1` library.

**MacOS**

```bash
brew install make gcc autoconf autobuild
```

**Linux (Ubuntu/Debian)**

```bash
sudo apt-get install build-essential automake libtool autoconf
```

### Elixir Dependency

Add `lib_secp256k1` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:lib_secp256k1, "~> 0.7.0"}
  ]
end
```

## Keypair Generation

The library allows generating secure random secret keys and deriving public keys in various formats.

### Generating a Random Keypair

You can generate a new random keypair with a specified public key format (`:compressed`, `:uncompressed`, or `:xonly`).

```elixir
# Generate a keypair with a compressed public key (33 bytes)
{seckey, pubkey} = Secp256k1.keypair(:compressed)

# Generate a keypair with an uncompressed public key (65 bytes)
{seckey, pubkey_uncompressed} = Secp256k1.keypair(:uncompressed)

# Generate a keypair with an x-only public key (32 bytes, used for Schnorr/Taproot)
{seckey, xonly_pubkey} = Secp256k1.keypair(:xonly)
```

### Deriving a Public Key

If you already have a secret key (32 bytes), you can derive the public key from it.

```elixir
seckey = <<0x1234...::256>> # Your 32-byte secret key

# Derive compressed public key
pubkey = Secp256k1.pubkey(seckey, :compressed)

# Derive x-only public key
xonly_pubkey = Secp256k1.pubkey(seckey, :xonly)
```

## ECDSA Signatures

ECDSA is the traditional signature scheme used in Bitcoin and other cryptocurrencies.

### Signing a Message

To sign a message, you first need to hash it (typically using SHA-256).

```elixir
# 1. Prepare the message hash
message = "Hello, World!"
msg_hash = :crypto.hash(:sha256, message)

# 2. Sign the hash with your secret key
# Returns a 64-byte compact signature
signature = Secp256k1.ecdsa_sign(msg_hash, seckey)
```

### Verifying a Signature

To verify a signature, you need the signature, the message hash, and the public key.

```elixir
# Verify the signature
is_valid = Secp256k1.ecdsa_valid?(signature, msg_hash, pubkey)
# => true
```

## Schnorr Signatures

Schnorr signatures (BIP-340) are simpler and more efficient than ECDSA. They use x-only public keys.

### Signing a Message

Schnorr signatures can sign a 32-byte hash or an arbitrary length message.

```elixir
# Signing a hash (recommended for Bitcoin)
msg_hash = :crypto.hash(:sha256, "Hello Schnorr")
signature = Secp256k1.schnorr_sign(msg_hash, seckey)
```

### Verifying a Signature

Verification requires the signature, the original message (or hash), and the x-only public key.

```elixir
# Derive x-only pubkey if you haven't already
xonly_pubkey = Secp256k1.pubkey(seckey, :xonly)

# Verify
is_valid = Secp256k1.schnorr_valid?(signature, msg_hash, xonly_pubkey)
# => true
```
