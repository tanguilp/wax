defmodule Wax.AttestationStatementFormat.None do
  @moduledoc false

  @behaviour Wax.AttestationStatementFormat

  @impl Wax.AttestationStatementFormat
  def verify(_attstmt, _auth_data, _client_data_hash, %Wax.Challenge{attestation: "none"}) do
    {:ok, {:none, nil, nil}}
  end

  def verify(_attstmt, _auth_data, _client_data_hash, _challenge) do
    {:error,
     %Wax.AttestationVerificationError{
       type: :none,
       reason: :invalid_attestation_conveyance_preference
     }}
  end
end
