defmodule Wax.MixProject do
  use Mix.Project

  def project do
    [
      app: :wax,
      version: "0.1.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Wax.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.1"},
      {:httpoison, github: "edgurgel/httpoison", tag: "v1.5.0"},
      {:cbor, github: "yjh0502/cbor-erlang", ref: "b5c9dbc2de15753b2db15e13d88c11738c2ac292"},
      {:x509, github: "voltone/x509", tag: "v0.5.1"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
