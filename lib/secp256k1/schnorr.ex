defmodule Secp256k1.Schnorr do
  @moduledoc false

  import Secp256k1.Guards

  @spec sign(message :: binary(), seckey :: Secp256k1.seckey()) :: Secp256k1.schnorr_sig()
  def sign(message, seckey) when is_hash(message), do: sign32(message, seckey)

  def sign(message, seckey) when is_binary(message), do: sign_custom(message, seckey)

  @spec sign32(msg_hash :: Secp256k1.hash(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.schnorr_sig()
  def sign32(msg_hash, seckey) when is_hash(msg_hash) and is_seckey(seckey) do
    sign32(msg_hash, seckey, :crypto.strong_rand_bytes(32))
  end

  @spec sign32(
          msg_hash :: Secp256k1.hash(),
          seckey :: Secp256k1.seckey(),
          aux :: <<_::32, _::_*8>>
        ) :: Secp256k1.schnorr_sig()
  def sign32(_msg_hash, _seckey, _aux), do: :erlang.nif_error({:error, :not_loaded})

  @spec sign_custom(message :: binary(), seckey :: Secp256k1.seckey()) :: Secp256k1.schnorr_sig()
  def sign_custom(message, seckey) when is_seckey(seckey) do
    sign_custom(message, seckey, :crypto.strong_rand_bytes(32))
  end

  @spec sign_custom(message :: binary(), seckey :: Secp256k1.seckey(), aux :: <<_::32, _::_*8>>) ::
          Secp256k1.schnorr_sig()
  def sign_custom(_message, _seckey, _aux), do: :erlang.nif_error({:error, :not_loaded})

  @spec valid?(
          signature :: Secp256k1.schnorr_sig(),
          message :: binary(),
          pubkey :: Secp256k1.xonly_pubkey()
        ) :: boolean()
  def valid?(_signature, _message, _pubkey), do: :erlang.nif_error({:error, :not_loaded})

  # internal NIF related

  @on_load :load_nifs

  def load_nifs do
    :lib_secp256k1
    |> Application.app_dir("priv/schnorrsig")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
