defmodule Secp256k1.Extrakeys do
  @moduledoc false

  import Secp256k1.Guards

  @spec xonly_pubkey(Secp256k1.seckey()) :: Secp256k1.xonly_pubkey()
  def xonly_pubkey(seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  # internal NIF related

  @on_load :load_nifs

  @dialyzer {:no_return, xonly_pubkey: 1}

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/extrakeys")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
