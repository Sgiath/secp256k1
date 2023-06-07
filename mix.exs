defmodule Secp256k1.MixProject do
  use Mix.Project

  @version "0.3.2"

  def project do
    [
      app: :lib_secp256k1,
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
      homepage_url: "https://sgiath.dev/libraries#secp256k1",
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
      {:ex_check, "~> 0.15", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev], runtime: false},
      {:dialyxir, "~> 1.3", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.29", only: [:dev], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev], runtime: false},
      {:mix_test_watch, "~> 1.1", only: [:dev], runtime: false}
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
