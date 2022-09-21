defmodule Secp256k1 do
  @moduledoc false

  require Logger

  @dialyzer {:no_return, mine_seckey: 1, pubkey: 1, sign: 2, verify: 3}

  @type seckey() :: <<_::32, _::_*8>>
  @type pubkey() :: <<_::32, _::_*8>>
  @type signature() :: <<_::64, _::_*8>>

  @spec gen_seckey :: seckey()
  def gen_seckey, do: :crypto.strong_rand_bytes(32)

  @spec mine_seckey(prefix :: <<_::_*8>>) :: {:ok, seckey()}
  defdelegate mine_seckey(prefix), to: Secp256k1.Extrakeys

  @spec pubkey(seckey :: seckey()) :: {:ok, pubkey()} | {:error, String.t()}
  defdelegate pubkey(seckey), to: Secp256k1.Extrakeys, as: :xonly_pubkey

  @spec sign(message :: binary(), seckey :: seckey()) :: {:ok, signature()} | {:error, String.t()}
  defdelegate sign(message, seckey), to: Secp256k1.Schnorr

  @spec verify(signature :: signature(), message :: binary(), pubkey :: pubkey()) ::
          :valid | :invalid
  defdelegate verify(signature, message, pubkey), to: Secp256k1.Schnorr

  @spec shared_secret(seckey :: seckey(), pubkey :: pubkey()) :: seckey()
  def shared_secret(seckey, pubkey) do
    :crypto.compute_key(:ecdh, <<0x02>> <> pubkey, seckey, :secp256k1)
  end

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
