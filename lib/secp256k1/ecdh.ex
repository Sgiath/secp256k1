defmodule Secp256k1.ECDH do
  @moduledoc false

  import Secp256k1.Guards

  @spec ecdh(seckey :: Secp256k1.seckey(), pubkey :: Secp256k1.pubkey()) ::
          Secp256k1.shared_secret()
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
