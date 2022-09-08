defmodule Secp256k1Test do
  use ExUnit.Case, async: true

  doctest Secp256k1

  setup do
    seckey = "eea73e861ec4ebda129c8fac849d28a244d43e0e51092736a704732c5377e9d2"
    pubkey = "8ab190faee92eda6b14a402e28229762015d8ce464b4c9e9593e466cecbef015"
    message = "1bb96f5c4738df288c57eed39c16b87fc5e3d863c689cca7f6d0f3cb92e04ec4"

    signature =
      "ab344b9d1956bb4a17ac73f16b099faad1484271e41821a636af2260d39d94850dc0823dec7ec5acfbf6323feb43482632feb87b5f8ee7aa2b982f0d775f8098"

    {:ok,
     %{
       seckey: Base.decode16!(seckey, case: :lower),
       pubkey: Base.decode16!(pubkey, case: :lower),
       message: Base.decode16!(message, case: :lower),
       signature: Base.decode16!(signature, case: :lower)
     }}
  end

  test "generate seckey" do
    seckey = Secp256k1.gen_seckey()
    assert byte_size(seckey) == 32
  end

  test "correctly derive pubkey", %{seckey: seckey, pubkey: pubkey} do
    assert {:ok, ^pubkey} = Secp256k1.pubkey(seckey)
  end

  test "correctly validate signature", %{pubkey: pubkey, message: message, signature: signature} do
    assert :valid = Secp256k1.verify(signature, message, pubkey)
  end

  test "generate and validate sign32", %{seckey: seckey, pubkey: pubkey, message: message} do
    assert {:ok, signature} = Secp256k1.sign(message, seckey)
    assert :valid == Secp256k1.verify(signature, message, pubkey)
  end

  test "generate and validate sign_custom", %{seckey: seckey, pubkey: pubkey} do
    message = "hello"

    assert {:ok, signature} = Secp256k1.sign(message, seckey)
    assert :valid == Secp256k1.verify(signature, message, pubkey)
  end

  test "does not validate invalid signature", %{pubkey: pubkey, signature: signature} do
    assert :invalid == Secp256k1.verify(signature, "hello", pubkey)
  end

  test "encrypt / decrypt", %{seckey: sec1, pubkey: pub1} do
    sec2 = Secp256k1.gen_seckey()
    {:ok, pub2} = Secp256k1.pubkey(sec2)

    shared1 = Secp256k1.shared_secret(sec1, pub2)
    shared2 = Secp256k1.shared_secret(sec2, pub1)

    assert shared1 == shared2

    message = "hello"

    {encrypted, iv} = Secp256k1.encrypt(message, shared1)
    assert message == Secp256k1.decrypt(encrypted, shared2, iv)
  end
end
