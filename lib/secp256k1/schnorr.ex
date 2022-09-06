defmodule Secp256k1.Schnorr do
  @moduledoc false

  @on_load :load_nifs

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/nif")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @spec xonly_pubkey(Secp256k1.seckey()) :: {:ok, Secp256k1.pubkey()} | {:error, String.t()}
  def xonly_pubkey(_seckey) do
    exit(:nif_not_loaded)
  end

  @spec sign32(message :: <<_::32, _::_*8>>, Secp256k1.seckey()) ::
          {:ok, Secp256k1.signature()} | {:error, String.t()}
  def sign32(_message, _seckey) do
    exit(:nif_not_loaded)
  end

  @spec sign_custom(message :: binary(), Secp256k1.seckey()) ::
          {:ok, Secp256k1.signature()} | {:error, String.t()}
  def sign_custom(_message, _seckey) do
    exit(:nif_not_loaded)
  end

  @spec verify(Secp256k1.signature(), message :: binary(), Secp256k1.seckey()) ::
          :valid | :invalid
  def verify(_signature, _message, _seckey) do
    exit(:nif_not_loaded)
  end
end
