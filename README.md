# Secp256k1

Elixir bindings for [secp256k1](https://github.com/bitcoin-core/secp256k1) library

## Installation

The package can be installed by adding `secp256k1` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:secp256k1, git: "https://git.sr.ht/~sgiath/secp256k1"}
  ]
end
```

## Features

- [x] generate secure random seckey
- [x] derive pubkey and serialize it in compressed, uncompressed or xonly format
- [x] generate and validate Schnorr signature
- [x] compute Diffie-Hellman secret
- [ ] standard EC signatures
- [ ] key tweaking
