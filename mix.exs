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
      {:jason, "~> 1.1"},
      {:httpoison, "~> 1.6"},
      {:cbor, github: "yjh0502/cbor-erlang", ref: "b5c9dbc2de15753b2db15e13d88c11738c2ac292"},
      {:x509, "~> 0.8"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
