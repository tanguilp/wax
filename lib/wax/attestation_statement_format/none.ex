defmodule Wax.AttestationStatementFormat.None do
  @moduledoc false

  @behaviour Wax.AttestationStatementFormat

  @impl Wax.AttestationStatementFormat
  def verify(_attstmt, _auth_data, _client_data_hash, _verify_trust_root) do
    {:ok, {:none, nil, nil}}
  end
end
