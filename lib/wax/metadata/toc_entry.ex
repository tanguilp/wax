defmodule Wax.Metadata.TOCEntry do
  @enforce_keys [:status_reports, :time_of_last_status_change]

  defstruct [
    :aaid,
    :aaguid,
    :attestation_certificate_key_identifiers,
    :hash,
    :url,
    :biometric_status_reports,
    :status_reports,
    :time_of_last_status_change,
    :rogue_list_url,
    :rogue_list_hash
  ]

  @type t :: %__MODULE__{
    aaid: String.t() | nil,
    aaguid: String.t() | nil,
    attestation_certificate_key_identifiers: [String.t()],
    hash: String.t() | nil,
    url: String.t() | nil,
    biometric_status_reports: [__MODULE__.BiometricStatusReport.t()],
    status_reports: [__MODULE__.StatusReport.t()],
    time_of_last_status_change: Date.t(),
    rogue_list_url: String.t() | nil,
    rogue_list_hash: String.t() | nil
  }

  defmodule BiometricStatusReport do
    @enforce_keys [:cert_level, :modality]

    defstruct [
      :cert_level,
      :modality,
      :effective_date,
      :certification_descriptor,
      :certificate_number,
      :certification_policy_version,
      :certification_requirements_version
    ]

    @type t :: %__MODULE__{
      cert_level: non_neg_integer(),
      modality: non_neg_integer(),
      effective_date: String.t() | nil,
      certification_descriptor: String.t() | nil,
      certificate_number: String.t() | nil,
      certification_policy_version: String.t() | nil,
      certification_requirements_version: String.t() | nil
    }
  end

  defmodule StatusReport do
    @enforce_keys [:status]

    @type status ::
    :not_fido_certified
    | :fido_certified
    | :user_verification_bypass
    | :attestation_key_compromise
    | :user_key_remote_compromise
    | :user_key_physical_compromise
    | :update_available
    | :revoked
    | :self_assertion_submitted
    | :fido_certified_l1
    | :fido_certified_l1plus
    | :fido_certified_l2
    | :fido_certified_l2plus
    | :fido_certified_l3
    | :fido_certified_l3plus

    defstruct [
      :status,
      :effective_date,
      :certificate,
      :url,
      :certification_descriptor,
      :certificate_number,
      :certification_policy_version,
      :certification_requirements_version
    ]

    @type t :: %__MODULE__{
      status: status(),
      effective_date: Date.t() | nil,
      certificate: String.t() | nil,
      url: String.t() | nil,
      certification_descriptor: String.t() | nil,
      certificate_number: String.t() | nil,
      certification_policy_version: String.t() | nil,
      certification_requirements_version: String.t() | nil
    }
  end
end
