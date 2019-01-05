defmodule Wax.AttestedCredentialData do
  @enforce_keys [
    :aaguid,
    :credential_id,
    :credential_public_key
  ]

  defstruct [
    :aaguid,
    :credential_id,
    :credential_public_key
  ]

  @type t :: %__MODULE__{
    aaguid: binary(),
    credential_id: binary(),
    credential_public_key: map()
  }

  def new(aaguid, credential_id, credential_public_key) do
    %__MODULE__{
    aaguid: aaguid,
    credential_id: credential_id,
    credential_public_key: credential_public_key
    }
  end
end
