defmodule Secp256k1.Schnorr do
  @moduledoc false

  @type seckey() :: <<_::32, _::_*8>>
  @type pubkey() :: <<_::32, _::_*8>>
  @type signature() :: <<_::64, _::_*8>>

  @on_load :load_nifs

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/nif")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @spec xonly_pubkey(seckey()) :: {:ok, pubkey()} | {:error, String.t()}
  def xonly_pubkey(_seckey) do
    raise "NIF not loaded"
  end

  @spec sign32(message :: <<_::32, _::_*8>>, seckey()) ::
          {:ok, signature()} | {:error, String.t()}
  def sign32(_message, _seckey) do
    raise "NIF not loaded"
  end

  @spec sign_custom(message :: binary(), seckey()) :: {:ok, signature()} | {:error, String.t()}
  def sign_custom(_message, _seckey) do
    raise "NIF not loaded"
  end

  @spec verify(signature(), message :: binary(), seckey()) :: :valid | :invalid
  def verify(_signature, _message, _seckey) do
    raise "NIF not loaded"
  end
end
