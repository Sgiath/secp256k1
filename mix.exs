defmodule Secp256k1.MixProject do
  use Mix.Project

  def project do
    [
      app: :secp256k1,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: deps(),

      # Elixir make
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_clean: ["clean"],

      # Docs
      name: "secp256k1",
      source_url: "https://git.sr.ht/~sgiath/secp256k1",
      homepage_url: "https://git.sr.ht/~sgiath/secp256k1",
      description: """
      Library wrapping around secp256k1 Bitcoin library
      """,
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:elixir_make, "~> 0.6", runtime: false},
      {:ex_doc, "~> 0.28", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:mix_test_watch, "~> 1.1", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [
      authors: [
        "Sgiath <sgiath@sgiath.dev>"
      ],
      main: "overview",
      formatters: ["html"],
      source_url_patter: "https://git.sr.ht/~sgiath/secp256k1/tree/master/item/%{path}#L%{line}",
      extra_section: "Guides",
      extras: extras(),
      groups_for_extras: groups_for_extras(),
      nest_modules_by_prefix: [
        Spaceboy.Middleware
      ]
    ]
  end

  defp extras do
    [
      # Introduction
      "docs/introduction/overview.md",
      "docs/introduction/installation.md"
    ]
  end

  defp groups_for_extras do
    [
      Introduction: ~r/docs\/introduction\/.?/,
      Guides: ~r/docs\/guides\/.?/
    ]
  end
end
