defmodule Wax.AttestationStatementFormat do
  @typedoc """
  The attestation statement format
  """
  @type statement_format ::
    :packed
    | :tpm
    | :android_key
    | :android_safetynet
    | :fido_u2f
    | :none

  @callback verify(Wax.Attestation.statement(),
                   Wax.AuthenticatorData.t(),
                   Wax.ClientData.hash(),
                   Wax.Challenge.t())
  :: {:ok, Wax.Attestation.result()} | {:error, any()}
end
