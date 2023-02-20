defmodule Wax.MixProject do
  use Mix.Project

  def project do
    [
      app: :wax_,
      description: "FIDO2 / WebAuthn server library",
      version: "0.6.1",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: [:asn1 | Mix.compilers()],
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
      extra_applications: [:logger, :inets],
      mod: {Wax.Application, []}
    ]
  end

  defp deps do
    [
      {:asn1_compiler, "~> 0.1.0", runtime: false},
      {:cbor, "~> 1.0"},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
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
