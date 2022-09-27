defmodule Secp256k1Test.EC do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.EC

  doctest Secp256k1.EC

  setup_all do
    {:ok,
     %{
       seckey: d("1111111111111111111111111111111111111111111111111111111111111111"),
       pubkey_compressed: d("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"),
       pubkey_uncompressed:
         d(
           "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1"
         )
     }}
  end

  test "sucessful", %{seckey: seckey, pubkey_compressed: pc, pubkey_uncompressed: pu} do
    assert EC.pubkey(seckey) == pc
    assert EC.pubkey(seckey, compress: true) == pc
    assert EC.pubkey(seckey, compress: false) == pu

    assert EC.compressed_pubkey(seckey) == pc
    assert EC.uncompressed_pubkey(seckey) == pu

    assert EC.compress_pubkey(pu) == pc
    assert EC.decompress_pubkey(pc) == pu
  end
end
