defmodule Wax.MixProject do
  use Mix.Project

  def project do
    [
      app: :wax,
      description: "FIDO2 / WebAuthn server library",
      version: "0.2.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: Mix.compilers ++ [:asn],
      dialyzer: [plt_add_apps: [:mix]],
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"]
      ],
      package: package(),
      source_url: "https://github.com/tanguilp/wax"
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

  def package() do
    [
      files: ~w(asn1 lib .formatter.exs mix.exs README* LICENSE* CHANGELOG*),
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/wax"}
    ]
  end
end
