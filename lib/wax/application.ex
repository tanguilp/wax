defmodule Wax.Application do
  @moduledoc false

  use Application
    import Supervisor.Spec

  def start(_type, _args) do
    Wax.AttestationStatementFormat.AndroidKey.install_asn1_module()

    children = [
      worker(Wax.Metadata, [])
    ]

    opts = [strategy: :one_for_one, name: Wax.Supervisor]

    Supervisor.start_link(children, opts)
  end
end
