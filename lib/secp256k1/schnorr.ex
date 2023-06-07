defmodule Secp256k1.Schnorr do
  @moduledoc """
  Module implementing Schnorr signatures as defined in BIP340
  """

  import Secp256k1.Guards

  @doc """
  Generate Schnorr signature of message (can be hash or custom length message)
  """
  @spec sign(message :: binary(), seckey :: Secp256k1.seckey()) :: Secp256k1.schnorr_sig()
  def sign(message, seckey) when is_hash(message), do: sign32(message, seckey)

  def sign(message, seckey) when is_binary(message), do: sign_custom(message, seckey)

  @doc """
  Generate Schnorr signature of a hash (AUX is randomly generated)
  """
  @spec sign32(msg_hash :: Secp256k1.hash(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.schnorr_sig()
  def sign32(msg_hash, seckey) when is_hash(msg_hash) and is_seckey(seckey) do
    sign32(msg_hash, seckey, :crypto.strong_rand_bytes(32))
  end

  @doc """
  Generate Schnorr signature of a hash and specify AUX - NOT RECOMMENDED
  """
  @spec sign32(
          msg_hash :: Secp256k1.hash(),
          seckey :: Secp256k1.seckey(),
          aux :: <<_::32, _::_*8>>
        ) :: Secp256k1.schnorr_sig()
  def sign32(_msg_hash, _seckey, _aux), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Generate Schnorr signature of arbitrary message (AUX is randomly generated)
  """
  @spec sign_custom(message :: binary(), seckey :: Secp256k1.seckey()) :: Secp256k1.schnorr_sig()
  def sign_custom(message, seckey) when is_seckey(seckey) do
    sign_custom(message, seckey, :crypto.strong_rand_bytes(32))
  end

  @doc """
  Generate Schnorr signature of a arbitrary message and specify AUX - NOT RECOMMENDED
  """
  @spec sign_custom(message :: binary(), seckey :: Secp256k1.seckey(), aux :: <<_::32, _::_*8>>) ::
          Secp256k1.schnorr_sig()
  def sign_custom(_message, _seckey, _aux), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Validate Schnorr signature
  """
  @spec valid?(
          signature :: Secp256k1.schnorr_sig(),
          message :: binary(),
          pubkey :: Secp256k1.xonly_pubkey()
        ) :: boolean()
  def valid?(_signature, _message, _pubkey), do: :erlang.nif_error({:error, :not_loaded})

  # internal NIF related

  @on_load :load_nifs

  defp load_nifs do
    :secp256k1
    |> Application.app_dir("priv/schnorrsig")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
