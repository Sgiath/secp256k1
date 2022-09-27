defmodule Secp256k1.ECDH do
  @moduledoc ~S"""
  EC Diffie-Hellman
  """
  @moduledoc authors: ["sgiath <secp256k1@sgiath.dev>"]

  import Secp256k1.Guards

  @typedoc "Shared secret is 32 bytes long binary"
  @type shared_secret() :: <<_::32, _::_*8>>

  @doc """
  Compute an EC Diffie-Hellman secret in constant time

  It accepts pubkey only in compressed or uncompressed format (not xonly format). If you need to
  compute ECDH from xonly pubkey you can prepend it with 0x02 byte:

      ecdh(seckey, <<0x02, xonly_pubkey::binary>>)

  """
  @spec ecdh(seckey :: Secp256k1.seckey(), pubkey :: Secp256k1.pubkey()) :: shared_secret()
  def ecdh(seckey, pubkey)
      when is_seckey(seckey) and (is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey)) do
    exit(:nif_not_loaded)
  end

  # internal NIF related

  @on_load :load_nifs

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/ecdh")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
