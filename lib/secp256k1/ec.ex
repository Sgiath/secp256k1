defmodule Secp256k1.EC do
  @moduledoc false

  import Secp256k1.Guards

  @spec pubkey(seckey :: Secp256k1.seckey(), opts :: Keyword.t()) ::
          Secp256k1.compressed_pubkey() | Secp256k1.uncompressed_pubkey()
  def pubkey(seckey, opts \\ []) when is_seckey(seckey) do
    if Keyword.get(opts, :compress, true) do
      compressed_pubkey(seckey)
    else
      uncompressed_pubkey(seckey)
    end
  end

  @spec compressed_pubkey(seckey :: Secp256k1.seckey()) :: Secp256k1.compressed_pubkey()
  def compressed_pubkey(seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @spec uncompressed_pubkey(seckey :: Secp256k1.seckey()) :: Secp256k1.uncompressed_pubkey()
  def uncompressed_pubkey(seckey) when is_seckey(seckey) do
    exit(:nif_not_loaded)
  end

  @spec compress_pubkey(pubkey :: Secp256k1.uncompressed_pubkey()) ::
          Secp256k1.compressed_pubkey()
  def compress_pubkey(pubkey) when is_uncompressed_pubkey(pubkey) do
    exit(:nif_not_loaded)
  end

  @spec decompress_pubkey(pubkey :: Secp256k1.compressed_pubkey()) ::
          Secp256k1.uncompressed_pubkey()
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
