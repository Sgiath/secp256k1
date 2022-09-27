defmodule Secp256k1.EC do
  @moduledoc ~S"""
  Module implementing pubkey derivation for EC secp256k1
  """
  @moduledoc authors: ["sgiath <secp256k1@sgiath.dev>"]

  import Secp256k1.Guards

  @typedoc "Standard pubkey serialized in compressed format is 33 bytes long"
  @type compressed() :: <<_::33, _::_*8>>

  @typedoc "Standard pubkey serialized in uncompressed format is 65 bytes long"
  @type uncompressed() :: <<_::65, _::_*8>>

  @typedoc "Standard pubkey can be serialized as compressed or uncompressed"
  @type pubkey() :: compressed() | uncompressed()

  @doc ~S"""
  Derive pubkey from seckey

  It can serialize it in compressed (default) or uncompressed format

  ## Options

  * `compress` (default `true`) - serialize in compressed form (33 bytes) if `false` generate
    decompressed form (65 bytes)

  """
  @spec pubkey(seckey :: Secp256k1.seckey(), opts :: Keyword.t()) :: pubkey()
  def pubkey(seckey, opts \\ []) when is_seckey(seckey) do
    if Keyword.get(opts, :compress, true) do
      compressed_pubkey(seckey)
    else
      uncompressed_pubkey(seckey)
    end
  end

  @doc """
  Derive pubkey from seckey and serialize it in compressed format (33 bytes)
  """
  @spec compressed_pubkey(seckey :: Secp256k1.seckey()) :: compressed()
  def compressed_pubkey(seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @doc """
  Derive pubkey from seckey and serialize it in uncompressed format (65 bytes)
  """
  @spec uncompressed_pubkey(seckey :: Secp256k1.seckey()) :: uncompressed()
  def uncompressed_pubkey(seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @doc """
  Convert uncompressed pubkey to compressed one
  """
  @spec compress_pubkey(pubkey :: uncompressed()) :: compressed()
  def compress_pubkey(pubkey) when is_uncompressed_pubkey(pubkey) do
    exit(:nif_not_loaded)
  end

  @doc """
  Convert compressed pubkey to uncompressed one
  """
  @spec decompress_pubkey(pubkey :: compressed()) :: uncompressed()
  def decompress_pubkey(pubkey) when is_compressed_pubkey(pubkey) do
    exit(:nif_not_loaded)
  end

  # internal NIF related

  @on_load :load_nifs

  @dialyzer {:no_return, pubkey: 1, pubkey: 2}

  defp load_nifs do
    :secp256k1
    |> Application.app_dir("priv/ec")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
