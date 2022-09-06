defmodule Secp256k1.Schnorr do
  @moduledoc false

  @on_load :load_nif

  def load_nif do
  end

  def xonly_pubkey(_seckey) do
    raise "NIF not loaded"
  end

  def sign32(_message, _seckey) do
    raise "NIF not loaded"
  end

  def sign_custom(_message, _seckey) do
    raise "NIF not loaded"
  end

  def verify(_signature, _message, _seckey) do
    raise "NIF not loaded"
  end
end
