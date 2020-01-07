defmodule Wax.Challenge do
  @enforce_keys [
    :bytes,
    :origin,
    :rp_id,
    :trusted_attestation_types,
    :verify_trust_root,
    :issued_at,
    :timeout
  ]

  defstruct [
    :bytes,
    :origin,
    :rp_id,
    :user_verified_required,
    :exp,
    :token_binding_status,
    :allow_credentials,
    :trusted_attestation_types,
    :verify_trust_root,
    :acceptable_authenticator_statuses,
    :issued_at,
    :timeout
  ]

  @type t :: %__MODULE__{
    bytes: binary(),
    origin: String.t(),
    rp_id: String.t(),
    user_verified_required: boolean(),
    exp: non_neg_integer() | nil,
    token_binding_status: any(),
    allow_credentials: [binary()],
    trusted_attestation_types: [Wax.Attestation.type()] | (Wax.Attestation.result() -> boolean()),
    verify_trust_root: boolean(),
    acceptable_authenticator_statuses: [Wax.Metadata.TOCEntry.StatusReport.status()],
    issued_at: integer(),
    timeout: non_neg_integer()
  }

  @doc false

  @spec new([{Wax.CredentialId.t(), Wax.CoseKey.t()}], Wax.parsed_opts()) :: t()
  def new(allow_credentials \\ [],
          %{origin: origin,
            rp_id: rp_id,
            user_verified_required: uvr,
            trusted_attestation_types: trusted_attestation_types,
            verify_trust_root: verify_trust_root,
            acceptable_authenticator_statuses: acceptable_authenticator_statuses,
            issued_at: issued_at,
            timeout: timeout
          })
  do
    %__MODULE__{
      bytes: random_bytes(),
      origin: origin,
      rp_id: rp_id,
      user_verified_required: uvr,
      allow_credentials: allow_credentials,
      trusted_attestation_types: trusted_attestation_types,
      verify_trust_root: verify_trust_root,
      acceptable_authenticator_statuses: acceptable_authenticator_statuses,
      issued_at: issued_at,
      timeout: timeout
    }
  end

  @spec random_bytes() :: binary
  defp random_bytes() do
    :crypto.strong_rand_bytes(32)
  end
end
