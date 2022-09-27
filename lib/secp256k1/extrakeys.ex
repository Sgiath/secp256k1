defmodule Secp256k1.Extrakeys do
  @moduledoc ~S"""
  Wrapper around ExtraKeys module of secp256k1 library to generate x-only pubkeys needed for
  Schnorr signatures
  """
  @moduledoc authors: ["sgiath <secp256k1@sgiath.dev>"]

  import Secp256k1.Guards

  @typedoc "x-only pubkey is 32 bytes long"
  @type xonly() :: <<_::32, _::_*8>>

  @doc """
  Derive xonly pubkey from seckey
  """
  @spec xonly_pubkey(Secp256k1.seckey()) :: xonly()
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
