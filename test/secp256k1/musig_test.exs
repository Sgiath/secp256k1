defmodule Secp256k1.MuSigTest do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.MuSig
  alias Secp256k1.Schnorr

  test "3-of-3 signing flow" do
    msg = :crypto.strong_rand_bytes(32)

    # 1. Generate keys
    signers =
      for _ <- 1..3 do
        {seckey, pubkey} = Secp256k1.keypair(:compressed)
        %{seckey: seckey, pubkey: pubkey}
      end

    pubkeys = Enum.map(signers, & &1.pubkey)

    # 2. Aggregate public keys
    {:ok, agg_xonly_pubkey, cache} = MuSig.pubkey_agg(pubkeys)
    assert byte_size(agg_xonly_pubkey) == 32

    # 3. Generate nonces
    # We need to keep the secnonce resource alive
    signers =
      Enum.map(signers, fn signer ->
        {:ok, secnonce, pubnonce} =
          MuSig.nonce_gen(signer.seckey, signer.pubkey, msg, cache, nil)

        Map.merge(signer, %{secnonce: secnonce, pubnonce: pubnonce})
      end)

    pubnonces = Enum.map(signers, & &1.pubnonce)

    # 4. Aggregate nonces
    aggnonce = MuSig.nonce_agg(pubnonces)
    assert byte_size(aggnonce) == 132

    # 5. Process nonces (create session)
    session = MuSig.nonce_process(aggnonce, msg, cache)
    assert byte_size(session) == 133

    # 6. Partial signing
    signers =
      Enum.map(signers, fn signer ->
        partial_sig =
          MuSig.partial_sign(signer.secnonce, signer.seckey, cache, session)

        Map.put(signer, :partial_sig, partial_sig)
      end)

    # 7. Verify partial signatures
    for signer <- signers do
      assert MuSig.partial_sig_verify(
               signer.partial_sig,
               signer.pubnonce,
               signer.pubkey,
               cache,
               session
             )
    end

    # 8. Aggregate signatures
    partial_sigs = Enum.map(signers, & &1.partial_sig)
    final_sig = MuSig.partial_sig_agg(session, partial_sigs)
    assert byte_size(final_sig) == 64

    # 9. Verify final signature
    assert Schnorr.valid?(final_sig, msg, agg_xonly_pubkey)
  end

  test "nonce reuse protection" do
    {seckey, pubkey} = Secp256k1.keypair(:compressed)
    {:ok, _, cache} = MuSig.pubkey_agg([pubkey])
    msg = :crypto.strong_rand_bytes(32)

    {:ok, secnonce, pubnonce} = MuSig.nonce_gen(seckey, pubkey, msg, cache, nil)
    aggnonce = MuSig.nonce_agg([pubnonce])
    session = MuSig.nonce_process(aggnonce, msg, cache)

    # First sign should succeed
    _sig = MuSig.partial_sign(secnonce, seckey, cache, session)

    # Second sign with same nonce resource should fail
    assert {:error, "nonce already used"} = MuSig.partial_sign(secnonce, seckey, cache, session)
  end
end
