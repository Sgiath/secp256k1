defmodule Secp256k1 do
  @moduledoc false

  require Logger

  @dialyzer {:no_return,
             pubkey: 2, schnorr_sign: 2, schnorr_valid?: 3, ecdh: 2, keypair: 1, keypair: 2}

  @type seckey() :: <<_::32, _::_*8>>

  @type pubkey_type() :: :compressed | :uncompressed | :xonly
  @type pubkey() :: Secp256k1.EC.pubkey() | Secp256k1.Extrakeys.xonly()

  @type schnorr_sig() :: Secp256k1.Schnorr.signature()

  # pubkey

  @spec pubkey(seckey :: seckey(), type :: pubkey_type()) :: pubkey()
  def pubkey(seckey, :xonly) do
    Secp256k1.Extrakeys.xonly_pubkey(seckey)
  end

  def pubkey(seckey, :compressed) do
    Secp256k1.EC.pubkey(seckey, compress: true)
  end

  def pubkey(seckey, :uncompressed) do
    Secp256k1.EC.pubkey(seckey, compress: false)
  end

  @spec keypair(type :: pubkey_type()) :: {seckey(), pubkey()}
  def keypair(type) do
    keypair(:crypto.strong_rand_bytes(32), type)
  end

  @spec keypair(seckey :: seckey(), type :: pubkey_type()) :: {seckey(), pubkey()}
  def keypair(seckey, type) do
    {seckey, Secp256k1.pubkey(seckey, type)}
  end

  # Schnorr sign

  @spec schnorr_sign(message :: binary(), seckey :: seckey()) :: schnorr_sig()
  defdelegate schnorr_sign(message, seckey), to: Secp256k1.Schnorr, as: :sign

  @spec schnorr_valid?(
          signature :: schnorr_sig(),
          message :: binary(),
          pubkey :: Secp256k1.Extrakeys.xonly()
        ) :: boolean()
  defdelegate schnorr_valid?(signature, message, pubkey), to: Secp256k1.Schnorr, as: :valid?

  # ECDH

  @spec ecdh(seckey :: seckey(), pubkey :: pubkey()) :: Secp256k1.ECDH.shared_secret()
  defdelegate ecdh(seckey, pubkey), to: Secp256k1.ECDH
end
