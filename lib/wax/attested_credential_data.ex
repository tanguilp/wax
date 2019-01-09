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

  @doc """
  Decode attested credential data

  We return the rest because the attested credential credential data is of variable
  size and can be followed by extensions
  """
  @spec decode(binary()) :: {:ok, {t() | nil, binary()}} | {:error, any()}
  def decode(<<>>), do: {:ok, {nil, <<>>}}

  def decode(
    <<
      aaguid::binary-size(16),
      credential_id_length::unsigned-big-integer-size(16),
      credential_id::binary-size(credential_id_length),
      credential_public_key::binary #FIXME: parse when there are extensions
      >>
  )
  do
    {:ok, {%__MODULE__{
      aaguid: aaguid,
      credential_id: credential_id,
      credential_public_key: :cbor.decode(credential_public_key)
    }, nil}}
  end

  def decode(_), do: {:error, :invalid_attested_credential_data}

  @spec decode!(binary()) :: t() | no_return()
  def decode!(bin) do
    case decode(bin) do
      {:ok, {acd, rest}} ->
        acd

      {:error, error} ->
        raise error
    end
  end
end
