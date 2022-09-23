defmodule Secp256k1.EC do
  @moduledoc false

  @on_load :load_nifs

  @dialyzer {:no_return, pubkey: 1, pubkey: 2}

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/ec")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  def pubkey(seckey, opts \\ []) do
    if Keyword.get(opts, :compress, true) do
      compressed_pubkey(seckey)
    else
      uncompressed_pubkey(seckey)
    end
  end

  @spec compressed_pubkey(seckey :: Secp256k1.seckey()) ::
          Secp256k1.compressed_pubkey() | {:error, String.t()}
  def compressed_pubkey(_seckey) do
    exit(:nif_not_loaded)
  end

  @spec uncompressed_pubkey(seckey :: Secp256k1.seckey()) ::
          Secp256k1.uncompressed_pubkey() | {:error, String.t()}
  def uncompressed_pubkey(_seckey) do
    exit(:nif_not_loaded)
  end

  @spec compress_pubkey(pubkey :: Secp256k1.uncompressed_pubkey()) ::
          Secp256k1.compressed_pubkey() | {:error, String.t()}
  def compress_pubkey(_pubkey) do
    exit(:nif_not_loaded)
  end

  @spec decompress_pubkey(pubkey :: Secp256k1.compressed_pubkey()) ::
          Secp256k1.uncompressed_pubkey() | {:error, String.t()}
  def decompress_pubkey(_pubkey) do
    exit(:nif_not_loaded)
  end
end
