defmodule Secp256k1.Guards do
  @moduledoc false

  # seckey
  defguard is_seckey(seckey) when is_binary(seckey) and byte_size(seckey) == 32

  # pubkey
  defguard is_compressed_pubkey(pubkey) when is_binary(pubkey) and byte_size(pubkey) == 33
  defguard is_uncompressed_pubkey(pubkey) when is_binary(pubkey) and byte_size(pubkey) == 65
  defguard is_xonly_pubkey(pubkey) when is_binary(pubkey) and byte_size(pubkey) == 32

  defguard is_pubkey(pubkey)
           when is_compressed_pubkey(pubkey) or is_uncompressed_pubkey(pubkey) or
                  is_xonly_pubkey(pubkey)

  # signature
  defguard is_schnorr_sig(sig) when is_binary(sig) and byte_size(sig) == 64
end
