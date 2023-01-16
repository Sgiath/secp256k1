defmodule Secp256k1.MixProject do
  use Mix.Project

  @version "0.2.0"

  def project do
    [
      app: :secp256k1,
      version: @version,
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),

      # Elixir make
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_clean: ["clean"],

      # Docs
      name: "secp256k1",
      source_url: "https://github.com/Sgiath/secp256k1",
      homepage_url: "https://secp256k1.sgiath.dev",
      description: """
      Library wrapping around secp256k1 Bitcoin library
      """,
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # C compilation
      {:elixir_make, "~> 0.7", runtime: false},

      # Development
      {:ex_doc, "~> 0.29", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:mix_test_watch, "~> 1.1", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["WTFPL"],
      links: %{
        "C library" => "https://github.com/bitcoin-core/secp256k1",
        "GitHub" => "https://github.com/Sgiath/secp256k1"
      },
      files: [
        "lib",
        "LICENSE",
        "mix.exs",
        "README.md",
        "c_src/*.[ch]",
        "Makefile"
      ]
    ]
  end

  defp docs do
    [
      authors: ["sgiath <secp256k1@sgiath.dev>"],
      main: "readme",
      extras: ["README.md": [filename: "readme", title: "Overview"]],
      formatters: ["html"],
      source_ref: @version,
      source_url: "https://github.com/Sgiath/secp256k1"
    ]
  end
end
