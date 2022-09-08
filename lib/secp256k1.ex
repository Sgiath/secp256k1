defmodule Secp256k1 do
  @moduledoc false

  require Logger

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
end
