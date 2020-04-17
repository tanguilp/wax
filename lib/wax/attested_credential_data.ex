defmodule Wax.AttestedCredentialData do
  alias Wax.Utils

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
    credential_id: Wax.CredentialId.t(),
    credential_public_key: Wax.CoseKey.t()
  }

  @doc false
  @spec decode(binary()) :: {t(), binary()} | {:error, atom()}
  def decode(
    <<
      aaguid::binary-size(16),
      credential_id_length::unsigned-big-integer-size(16),
      credential_id::binary-size(credential_id_length),
      rest::binary
    >>
  )
  do
    with {:ok, credential_public_key, extensions} <- Utils.CBOR.decode(rest) do
      {
        %__MODULE__{
          aaguid: aaguid,
          credential_id: credential_id,
          credential_public_key: credential_public_key
        },
        extensions
      }
    end
  end

  def decode(_), do: {:error, :invalid_attested_credential_data}
end
