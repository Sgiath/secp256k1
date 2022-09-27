defmodule Secp256k1Test.Case do
  use ExUnit.CaseTemplate

  using do
    quote do
      import Secp256k1Test.Format
    end
  end
end
