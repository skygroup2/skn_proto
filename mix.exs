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
      extra_applications: [
        :logger,
        :gun,
        :cowlib,
        :idna,
        :certifi,
        :ssl_verify_fun
      ]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:gun, git: "https://github.com/gskynet/gun.git", branch: "master"},
      {:lager, "~> 3.8", override: true},
      {:jason, "~> 1.1"}
    ]
  end
end
