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
    :attestation,
    :bytes,
    :origin,
    :rp_id,
    :user_verified_required,
    :token_binding_status,
    :allow_credentials,
    :trusted_attestation_types,
    :verify_trust_root,
    :acceptable_authenticator_statuses,
    :issued_at,
    :timeout,
    android_key_allow_software_enforcement: false
  ]

  @type t :: %__MODULE__{
    attestation: String.t(),
    bytes: binary(),
    origin: String.t(),
    rp_id: String.t(),
    user_verified_required: boolean(),
    token_binding_status: any(),
    allow_credentials: [binary()],
    trusted_attestation_types: [Wax.Attestation.type()] | (Wax.Attestation.result() -> boolean()),
    verify_trust_root: boolean(),
    acceptable_authenticator_statuses: [Wax.Metadata.TOCEntry.StatusReport.status()],
    issued_at: integer(),
    timeout: non_neg_integer(),
    android_key_allow_software_enforcement: boolean()
  }

  @doc false

  @spec new([{Wax.CredentialId.t(), Wax.CoseKey.t()}], Wax.opts()) :: t()
  def new(allow_credentials \\ [], opts) do
    struct(
      __MODULE__,
      [allow_credentials: allow_credentials] ++ [bytes: random_bytes()] ++ opts
    )
  end

  @spec random_bytes() :: binary
  defp random_bytes() do
    :crypto.strong_rand_bytes(32)
  end
end
