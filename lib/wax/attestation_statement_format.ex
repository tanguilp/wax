defmodule Wax.AttestationStatementFormat do
  @callback verify(
              Wax.Attestation.statement(),
              Wax.AuthenticatorData.t(),
              Wax.ClientData.hash(),
              Wax.Challenge.t()
            ) ::
              {:ok, Wax.Attestation.result()} | {:error, any()}
end
