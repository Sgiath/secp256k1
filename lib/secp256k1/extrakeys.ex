defmodule Secp256k1.Extrakeys do
  @moduledoc false

  @on_load :load_nifs

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/extrakeys")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @spec xonly_pubkey(Secp256k1.seckey()) :: {:ok, Secp256k1.pubkey()} | {:error, String.t()}
  def xonly_pubkey(_seckey) do
    exit(:nif_not_loaded)
  end
end
