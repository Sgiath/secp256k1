defmodule Secp256k1.Guards do
  @moduledoc false

  defguard is_bin_size(data, size) when is_binary(data) and byte_size(data) == size

  defguard is_hash(data) when is_bin_size(data, 32)

  # seckey
  defguard is_seckey(seckey) when is_bin_size(seckey, 32)

  # pubkey
  defguard is_compressed_pubkey(pubkey) when is_bin_size(pubkey, 33)
  defguard is_uncompressed_pubkey(pubkey) when is_bin_size(pubkey, 65)
  defguard is_xonly_pubkey(pubkey) when is_bin_size(pubkey, 32)

  defguard is_pubkey(pubkey)
           when is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey) or
                  is_xonly_pubkey(pubkey)

  # signature
  defguard is_ecdsa_sig(sig) when is_bin_size(sig, 64)
  defguard is_schnorr_sig(sig) when is_bin_size(sig, 64)
end
