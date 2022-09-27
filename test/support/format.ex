defmodule Secp256k1Test.Format do
  def d(data), do: Base.decode16!(data, case: :lower)
  def e(data), do: Base.encode16(data, case: :lower)
end
