defmodule Secp256k1.MixProject do
  use Mix.Project

  def project do
    [
      app: :secp256k1,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Elixir make
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_clean: ["clean"]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:elixir_make, "~> 0.4", runtime: false}
    ]
  end
end
