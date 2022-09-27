defmodule Secp256k1Test.ECDH do
  use Secp256k1Test.Case, async: true

  alias Secp256k1.ECDH

  doctest Secp256k1.ECDH

  setup_all do
    {:ok,
     %{
       key1:
         {d("1111111111111111111111111111111111111111111111111111111111111111"),
          d("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")},
       key2:
         {d("2222222222222222222222222222222222222222222222222222222222222222"),
          d("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27")}
     }}
  end

  test "succesful", %{key1: {s1, p1}, key2: {s2, p2}} do
    assert ECDH.ecdh(s1, p2) == ECDH.ecdh(s2, p1)
  end
end
