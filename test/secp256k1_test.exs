defmodule Secp256k1Test do
  use ExUnit.Case
  doctest Secp256k1

  test "greets the world" do
    assert Secp256k1.hello() == :world
  end
end
