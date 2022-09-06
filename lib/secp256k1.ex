defmodule Secp256k1 do
  @moduledoc false

  require Logger

  def gen_seckey do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end

  @spec pubkey(seckey :: binary()) :: binary() | :error
  def pubkey(seckey) do
    seckey = Base.decode16!(seckey, case: :lower)

    unless byte_size(seckey) == 32 do
      raise ArgumentError
    end

    case Secp256k1.Schnorr.xonly_pubkey(seckey) do
      {:ok, pubkey} ->
        Base.encode16(pubkey, case: :lower)

      {:error, message} ->
        Logger.error(message)
        :error
    end
  end

  @spec sign(message :: binary(), seckey :: binary()) :: binary() | :error
  def sign(message, seckey) do
    message = Base.decode16!(message, case: :lower)
    seckey = Base.decode16!(seckey, case: :lower)

    unless byte_size(seckey) == 32 do
      raise ArgumentError
    end

    sig =
      if byte_size(message) == 32 do
        Secp256k1.Schnorr.sign32(message, seckey)
      else
        Secp256k1.Schnorr.sign_custom(message, seckey)
      end

    case sig do
      {:ok, sig} ->
        Base.encode16(sig, case: :lower)

      {:error, message} ->
        Logger.error(message)
        :error
    end
  end

  @spec verify(signature :: binary(), message :: binary(), seckey :: binary()) ::
          :valid | :invalid
  def verify(signature, message, seckey) do
    signature = Base.decode16!(signature, case: :lower)
    message = Base.decode16!(message, case: :lower)
    seckey = Base.decode16!(seckey, case: :lower)

    unless byte_size(signature) == 64 do
      raise ArgumentError
    end

    unless byte_size(seckey) == 32 do
      raise ArgumentError
    end

    Secp256k1.Schnorr.verify(signature, message, seckey)
  end
end
