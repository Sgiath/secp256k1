defmodule Secp256k1.Schnorr do
  @moduledoc false

  @on_load :load_nifs

  @dialyzer {:no_return, sign: 2}

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/schnorrsig")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @spec sign(message :: binary(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.signature() | {:error, String.t()}
  def sign(message, seckey) when byte_size(message) == 32, do: sign32(message, seckey)
  def sign(message, seckey), do: sign_custom(message, seckey)

  @spec sign32(message :: <<_::32, _::_*8>>, Secp256k1.seckey()) ::
          Secp256k1.signature() | {:error, String.t()}
  def sign32(_message, _seckey) do
    exit(:nif_not_loaded)
  end

  @spec sign_custom(message :: binary(), Secp256k1.seckey()) ::
          Secp256k1.signature() | {:error, String.t()}
  def sign_custom(_message, _seckey) do
    exit(:nif_not_loaded)
  end

  @spec verify(Secp256k1.signature(), message :: binary(), Secp256k1.pubkey()) ::
          :valid | :invalid
  def verify(_signature, _message, _pubkey) do
    exit(:nif_not_loaded)
  end
end
