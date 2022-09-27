defmodule Secp256k1.Schnorr do
  @moduledoc false

  import Secp256k1.Guards

  @spec sign(message :: binary(), seckey :: Secp256k1.seckey()) :: Secp256k1.schnorr_sig()
  def sign(message, seckey) when is_binary(message) and byte_size(message) == 32,
    do: sign32(message, seckey)

  def sign(message, seckey) when is_binary(message), do: sign_custom(message, seckey)

  @spec sign32(message :: <<_::32, _::_*8>>, Secp256k1.seckey()) :: Secp256k1.schnorr_sig()
  def sign32(_message, seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @spec sign_custom(message :: binary(), Secp256k1.seckey()) :: Secp256k1.schnorr_sig()
  def sign_custom(_message, seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @spec valid?(
          signature :: Secp256k1.schnorr_sig(),
          message :: binary(),
          pubkey :: Secp256k1.xonly_pubkey()
        ) :: boolean()
  def valid?(signature, message, pubkey)
      when is_schnorr_sig(signature) and is_binary(message) and is_xonly_pubkey(pubkey) do
    exit(:nif_not_loaded)
  end

  # internal NIF related

  @on_load :load_nifs

  @dialyzer {:no_return, sign: 2}

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/schnorrsig")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
