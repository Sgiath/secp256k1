defmodule Secp256k1.EC do
  @moduledoc ~S"""
  Module implementing pubkey derivation for EC secp256k1
  """
  @moduledoc authors: ["Sgiath <secp256k1@sgiath.dev>"]

  @on_load :load_nifs

  @dialyzer {:no_return, pubkey: 1, pubkey: 2}

  defp load_nifs do
    :secp256k1
    |> Application.app_dir("priv/ec")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @type compressed() :: <<_::33, _::_*8>>
  @type uncompressed() :: <<_::65, _::_*8>>
  @type pubkey() :: compressed() | uncompressed()

  @doc ~S"""
  Derive pubkey from seckey

  It can

  ## Options

  * `compress` (default `true`) - serialize in compressed form (33 bytes) if `false` generate
    decompressed form (65 bytes)

  """
  @spec pubkey(seckey :: Secp256k1.seckey(), opts :: Keyword.t()) :: pubkey()
  def pubkey(seckey, opts \\ []) do
    if Keyword.get(opts, :compress, true) do
      compressed_pubkey(seckey)
    else
      uncompressed_pubkey(seckey)
    end
  end

  @spec compressed_pubkey(seckey :: Secp256k1.seckey()) :: compressed()
  def compressed_pubkey(_seckey) do
    exit(:nif_not_loaded)
  end

  @spec uncompressed_pubkey(seckey :: Secp256k1.seckey()) :: uncompressed()
  def uncompressed_pubkey(_seckey) do
    exit(:nif_not_loaded)
  end

  @spec compress_pubkey(pubkey :: uncompressed()) :: compressed()
  def compress_pubkey(_pubkey) do
    exit(:nif_not_loaded)
  end

  @spec decompress_pubkey(pubkey :: compressed()) :: uncompressed()
  def decompress_pubkey(_pubkey) do
    exit(:nif_not_loaded)
  end
end
