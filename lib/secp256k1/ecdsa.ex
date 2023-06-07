defmodule Secp256k1.ECDSA do
  @moduledoc """
  Module implementing ECDSA pubkey derivation and signatures
  """

  import Secp256k1.Guards

  @doc """
  Derive pubkey from seckey

  ## Options
    - :compress (default true) - whether to format pubkey in compressed or uncompressed format
  """
  @spec pubkey(seckey :: Secp256k1.seckey(), opts :: Keyword.t()) ::
          Secp256k1.compressed_pubkey() | Secp256k1.uncompressed_pubkey()
  def pubkey(seckey, opts \\ []) when is_seckey(seckey) do
    if Keyword.get(opts, :compress, true) do
      compressed_pubkey(seckey)
    else
      uncompressed_pubkey(seckey)
    end
  end

  @doc """
  Derive compressed pubkey from seckey
  """
  @spec compressed_pubkey(seckey :: Secp256k1.seckey()) :: Secp256k1.compressed_pubkey()
  def compressed_pubkey(_seckey), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Derive uncompressed pubkey from seckey
  """
  @spec uncompressed_pubkey(seckey :: Secp256k1.seckey()) :: Secp256k1.uncompressed_pubkey()
  def uncompressed_pubkey(_seckey), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Convert uncompressed pubkey to compressed one
  """
  @spec compress_pubkey(pubkey :: Secp256k1.uncompressed_pubkey()) ::
          Secp256k1.compressed_pubkey()
  def compress_pubkey(_pubkey), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Convert compressed pubkey to uncompressed one
  """
  @spec decompress_pubkey(pubkey :: Secp256k1.compressed_pubkey()) ::
          Secp256k1.uncompressed_pubkey()
  def decompress_pubkey(_pubkey), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Generate ECDSA signature of message hash (AUX is randomly generated)
  """
  @spec sign(msg_hash :: Secp256k1.hash(), seckey :: Secp256k1.seckey()) ::
          Secp256k1.ecdsa_sig()
  def sign(msg_hash, seckey) when is_hash(msg_hash) and is_seckey(seckey) do
    sign(msg_hash, seckey, :crypto.strong_rand_bytes(32))
  end

  @doc """
  Generate ECDSA signature of message hash and specify AUX value - NOT RECOMMENDED
  """
  @spec sign(
          msg_hash :: Secp256k1.hash(),
          seckey :: Secp256k1.seckey(),
          aux :: <<_::256>>
        ) :: Secp256k1.ecdsa_sig()
  def sign(_msg_hash, _seckey, _aux), do: :erlang.nif_error({:error, :not_loaded})

  @doc """
  Check if ECDSA signature is valid
  """
  @spec valid?(
          signature :: Secp256k1.ecdsa_sig(),
          msg_hash :: Secp256k1.hash(),
          pubkey :: Secp256k1.compressed_pubkey()
        ) :: boolean()
  def valid?(_signature, _msg_hash, _pubkey), do: :erlang.nif_error({:error, :not_loaded})

  # internal NIF related

  @on_load :load_nifs

  defp load_nifs do
    :lib_secp256k1
    |> Application.app_dir("priv/ecdsa")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end
end
