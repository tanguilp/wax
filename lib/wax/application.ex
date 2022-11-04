defmodule Wax.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    children = [Wax.Metadata]

    opts = [strategy: :one_for_one, name: Wax.Supervisor]

    Supervisor.start_link(children, opts)
  end
end
