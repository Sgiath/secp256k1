defmodule Secp256k1 do
  @moduledoc false

  require Logger

  @dialyzer {:no_return, pubkey: 2, sign: 2, verify: 3, ecdh: 2, keypair: 1, keypair: 2}

  @type seckey() :: <<_::32, _::_*8>>

  @type pubkey_type() :: :compressed | :uncompressed | :xonly
  @type compressed_pubkey() :: <<_::33, _::_*8>>
  @type uncompressed_pubkey() :: <<_::65, _::_*8>>
  @type xonly_pubkey() :: <<_::32, _::_*8>>
  @type pubkey() :: compressed_pubkey() | uncompressed_pubkey() | xonly_pubkey()

  @type signature() :: <<_::64, _::_*8>>

  # pubkey

  @spec pubkey(seckey :: seckey(), type :: pubkey_type()) :: pubkey() | {:error, String.t()}
  def pubkey(seckey, :xonly) do
    Secp256k1.Extrakeys.xonly_pubkey(seckey)
  end

  def pubkey(seckey, :compressed) do
    Secp256k1.EC.pubkey(seckey, compress: true)
  end

  def pubkey(seckey, :uncompressed) do
    Secp256k1.EC.pubkey(seckey, compress: false)
  end

  def keypair(type) do
    keypair(:crypto.strong_rand_bytes(32), type)
  end

  def keypair(seckey, type) do
    {seckey, Secp256k1.pubkey(seckey, type)}
  end

  # Schnorr sign

  @spec sign(message :: binary(), seckey :: seckey()) :: signature() | {:error, String.t()}
  defdelegate sign(message, seckey), to: Secp256k1.Schnorr

  @spec verify(signature :: signature(), message :: binary(), pubkey :: xonly_pubkey()) ::
          :valid | :invalid | {:error, String.t()}
  defdelegate verify(signature, message, pubkey), to: Secp256k1.Schnorr

  # ECDH

  @spec ecdh(seckey :: seckey(), pubkey :: pubkey()) :: <<_::32, _::_*8>>
  defdelegate ecdh(seckey, pubkey), to: Secp256k1.ECDH
end
