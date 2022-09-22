defmodule Secp256k1 do
  @moduledoc false

  require Logger

  @dialyzer {:no_return, mine_seckey: 1, pubkey: 2, sign: 2, verify: 3}

  @type seckey() :: <<_::32, _::_*8>>

  @type pubkey_type() :: :compressed | :uncompressed | :xonly
  @type compressed_pubkey() :: <<_::33, _::_*8>>
  @type uncompressed_pubkey() :: <<_::65, _::_*8>>
  @type xonly_pubkey() :: <<_::32, _::_*8>>
  @type pubkey() :: compressed_pubkey() | uncompressed_pubkey() | xonly_pubkey()

  @type signature() :: <<_::64, _::_*8>>

  # seckey

  @spec gen_seckey :: seckey()
  def gen_seckey, do: :crypto.strong_rand_bytes(32)

  @spec mine_seckey(prefix :: <<_::_*8>>) :: {:ok, seckey()}
  defdelegate mine_seckey(prefix), to: Secp256k1.Extrakeys

  # pubkey

  @spec pubkey(seckey :: seckey(), type :: pubkey_type()) ::
          {:ok, pubkey()} | {:error, String.t()}
  def pubkey(seckey, :xonly) do
    Secp256k1.Extrakeys.xonly_pubkey(seckey)
  end

  def pubkey(seckey, :compressed) do
    Secp256k1.EC.pubkey(seckey, compress: true)
  end

  def pubkey(seckey, :uncompressed) do
    Secp256k1.EC.pubkey(seckey, compress: false)
  end

  # Schnorr sign

  @spec sign(message :: binary(), seckey :: seckey()) :: {:ok, signature()} | {:error, String.t()}
  defdelegate sign(message, seckey), to: Secp256k1.Schnorr

  @spec verify(signature :: signature(), message :: binary(), pubkey :: xonly_pubkey()) ::
          :valid | :invalid
  defdelegate verify(signature, message, pubkey), to: Secp256k1.Schnorr

  # ECDH

  @spec shared_secret(seckey :: seckey(), pubkey :: pubkey()) :: seckey()
  def shared_secret(seckey, pubkey) when byte_size(pubkey) == 32 do
    shared_secret(seckey, <<0x02>> <> pubkey)
  end

  def shared_secret(seckey, pubkey) when byte_size(pubkey) == 33 do
    :crypto.compute_key(:ecdh, pubkey, seckey, :secp256k1)
  end

  # AES

  @spec encrypt(binary(), shared_secret :: seckey()) ::
          {encrypted :: binary(), iv :: <<_::16, _::_*8>>}
  def encrypt(message, shared_secret) do
    iv = :crypto.strong_rand_bytes(16)
    {encrypt(message, shared_secret, iv), iv}
  end

  @spec encrypt(binary(), shared_secret :: seckey(), iv :: <<_::16, _::_*8>>) :: binary()
  def encrypt(message, shared_secret, iv) do
    :crypto.crypto_one_time(:aes_256_cbc, shared_secret, iv, message,
      encrypt: true,
      padding: :pkcs_padding
    )
  end

  @spec decrypt(message :: binary(), shared_secret :: seckey(), iv :: <<_::16, _::_*8>>) ::
          binary()
  def decrypt(message, shared_secret, iv) do
    :crypto.crypto_one_time(:aes_256_cbc, shared_secret, iv, message,
      encrypt: false,
      padding: :pkcs_padding
    )
  end
end
