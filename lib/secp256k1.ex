defmodule Secp256k1 do
  @moduledoc false

  def gen_seckey do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.encode16(case: :lower)
  end

  def pubkey(seckey) do
    seckey = Base.decode16!(seckey, case: :lower)

    unless byte_size(seckey) == 32 do
      raise ArgumentError
    end

    seckey
    |> Secp256k1.Schnorr.xonly_pubkey()
    |> Base.encode16(case: :lower)
  end

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

    Base.encode16(sig, case: :lower)
  end

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
