defmodule Wax.AttestationStatementFormat.None do
  @behaviour Wax.AttestationStatementFormat

  @impl Wax.AttestationStatementFormat
  def verify(_attstmt, _auth_data, _client_data_hash, _auth_data_bin) do
    {:ok, {:none, nil}}
  end
end
