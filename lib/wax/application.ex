defmodule Wax.Application do
  @moduledoc false

  use Application
    import Supervisor.Spec

  def start(_type, _args) do
    children = [
      worker(Wax.Metadata, [])
    ]

    opts = [strategy: :one_for_one, name: Wax.Supervisor]

    Supervisor.start_link(children, opts)
  end
end
