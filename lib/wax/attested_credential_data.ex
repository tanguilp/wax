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
    credential_public_key: Wax.CoseKey.t()
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

  In addition, the number of bytes read is returned so that extensions can be further parsed
  (and only when `with_appended_extensions` is `true`
  """
  @spec decode(binary(), boolean())
    :: {:ok, t()} |{:ok, {t() | non_neg_integer()}} | {:error, any()}

  def decode(
    <<
      aaguid::binary-size(16),
      credential_id_length::unsigned-big-integer-size(16),
      credential_id::binary-size(credential_id_length),
      rest::binary
    >>,
    with_appended_extensions
  )
  do
    if with_appended_extensions do
      {cbor, bytes_read} = cbor_decode_binary_unknown_length(rest, 1, byte_size(rest))

      {:ok,
        {
          %__MODULE__{
          aaguid: aaguid,
          credential_id: credential_id,
            credential_public_key: cbor
          }, bytes_read
        }
      }
    else
      {:ok,
        %__MODULE__{
          aaguid: aaguid,
          credential_id: credential_id,
          credential_public_key: :cbor.decode(rest)
        }
      }
    end
  end

  def decode(_, _), do: {:error, :invalid_attested_credential_data}

  @spec cbor_decode_binary_unknown_length(binary, non_neg_integer(), non_neg_integer())
    :: {any(), non_neg_integer()}

  def cbor_decode_binary_unknown_length(_bin, nb, max) when nb > max do
    raise "#{__MODULE__}: invalid CBOR decode error"
  end

  def cbor_decode_binary_unknown_length(bin, nb, max) do
    try do
      %{} = cpk = :cbor.decode(<<bin::binary-size(nb)>>)

      {cpk, nb}
    # yeah :cbor both throws and raises
    rescue
      _ ->
        cbor_decode_binary_unknown_length(bin, nb + 1, max)
    catch
      _ ->
        cbor_decode_binary_unknown_length(bin, nb + 1, max)
    end
  end
end
