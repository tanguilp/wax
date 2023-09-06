defmodule Wax.ExpiredChallengeError do
  defexception message: "Challenge has expired"
end

defmodule Wax.InvalidClientDataError do
  defexception [:reason]

  @impl true
  def message(%{reason: reason}) do
    "Invalid client data (reason: #{inspect(reason)})"
  end
end

defmodule Wax.InvalidCBORError do
  defexception message: "Invalid CBOR"
end

defmodule Wax.InvalidAuthenticatorDataError do
  defexception message: "Invalid authenticator data"
end

defmodule Wax.UnsupportedAttestationFormatError do
  defexception message: "Unsupported attestation format"
end

defmodule Wax.UntrustedAttestationTypeError do
  defexception [:type, :challenge]

  @impl true
  def message(%{type: type, challenge: challenge}) do
    "Untrusted attesation type #{type}, supported types are: " <>
      "#{inspect(challenge.trusted_attestation_types)}"
  end
end

defmodule Wax.InvalidSignatureError do
  defexception message: "Invalid signature"
end

defmodule Wax.UnsupportedSignatureAlgorithmError do
  defexception message: "Unsupported signature algorithm used"
end

defmodule Wax.AttestationVerificationError do
  defexception [:type, :reason]
  @type t :: %__MODULE__{
    type: Wax.Attestation.statement_format(),
    reason: atom()
  }

  @impl true
  def message(%{type: type, reason: reason}) do
    "Failed to verify attestation of type #{type} (reason: #{reason})"
  end
end

defmodule Wax.MetadataStatementNotFoundError do
  defexception message: "Authenticator metadata was not found"
end

defmodule Wax.AuthenticatorStatusNotAcceptableError do
  defexception [:status]

  @impl true
  def message(%{status: status}) do
    """
    Authenticator was not accepted. Its security might have been broken,
    or he's not sufficiently certified yet. Rejected status: #{status}
    """
  end
end
