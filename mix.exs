defmodule SknProto.MixProject do
  use Mix.Project

  def project do
    [
      app: :skn_proto,
      version: "0.1.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:hackney, git: "https://github.com/gskynet/hackney.git", branch: "master", override: true},
      {:gun, git: "https://github.com/gskynet/gun.git", branch: "master"},
      {:idna, "~> 6.0", override: true},
      {:httpoison, "~> 1.5"},
      {:lager, "~> 3.6", override: true},
      {:jason, "~> 1.1"}
    ]
  end
end
