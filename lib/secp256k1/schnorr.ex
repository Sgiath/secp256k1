defmodule Secp256k1.Schnorr do
  @moduledoc """
  Wrapper around shnorrsig module of secp256k1 library for making Schnorr signatures according to
  BIP 340
  """
  @moduledoc authors: ["sgiath <secp256k1@sgiath.dev>"]

  import Secp256k1.Guards

  @typedoc "Schnorr signature is 64 bytes binary"
  @type signature() :: <<_::64, _::_*8>>

  @doc """
  Generate signature of message with seckey
  """
  @spec sign(message :: binary(), seckey :: Secp256k1.seckey()) :: signature()
  def sign(message, seckey) when is_binary(message) and byte_size(message) == 32,
    do: sign32(message, seckey)

  def sign(message, seckey) when is_binary(message), do: sign_custom(message, seckey)

  @doc """
  Sign 32 byte binary message (hash) according to BIP 340
  """
  @spec sign32(message :: <<_::32, _::_*8>>, Secp256k1.seckey()) :: signature()
  def sign32(_message, seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @doc """
  Sign arbitrary long message  according to BIP 340
  """
  @spec sign_custom(message :: binary(), Secp256k1.seckey()) :: signature()
  def sign_custom(_message, seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @doc """
  Verify a Schnorr signature
  """
  @spec valid?(
          signature :: signature(),
          message :: binary(),
          pubkey :: Secp256k1.Extrakeys.xonly()
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
