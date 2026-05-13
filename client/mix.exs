defmodule Nym.MixProject do
  use Mix.Project

  @documentation "https://hexdocs.pm/nym"
  @git_repository "https://git.dupunkto.org/~dupunkto/nym"

  def project do
    [
      name: "Nym",
      app: :nym,
      version: "0.0.1-rc2",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Docs
      source_url: @git_repository,
      homepage_url: @documentation,
      description: description(),
      package: package(),
      docs: docs()
    ]
  end

  def description do
    "Identity provider and authentication layer"
  end

  defp package do
    [
      licenses: ["Unlicense"],
      links: %{"Sources" => @git_repository}
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:phoenix_live_view, "~> 1.0"},
      {:req, "~> 0.5.10"},

      # For documentation :)
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [
      main: "Nym",
      api_reference: false,
      authors: ["Robijntje"],
      formatters: ["html"]
    ]
  end
end
