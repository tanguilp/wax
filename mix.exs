defmodule Wax.MixProject do
  use Mix.Project

  def project do
    [
      app: :wax,
      version: "0.1.3",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: Mix.compilers ++ [:asn],
      dialyzer: [plt_add_apps: [:mix]],
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {Wax.Application, []}
    ]
  end

  defp deps do
    [
      {:cbor, "~> 1.0.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:httpoison, "~> 1.6"},
      {:jason, "~> 1.1"},
      {:x509, "~> 0.8"}
    ]
  end
end
