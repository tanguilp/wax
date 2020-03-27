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
    credential_id: Wax.CredentialId.t(),
    credential_public_key: Wax.CoseKey.t()
  }

  @doc false
  @spec decode(binary(), boolean()) :: {t(), non_neg_integer()}
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

      {
        %__MODULE__{
        aaguid: aaguid,
        credential_id: credential_id,
          credential_public_key: cbor
        },
        16 + 2 + credential_id_length + bytes_read
      }
    else
      {
        %__MODULE__{
          aaguid: aaguid,
          credential_id: credential_id,
          credential_public_key: :cbor.decode(rest)
        },
        16 + 2 + credential_id_length + byte_size(rest)
      }
    end
  end

  def decode(_, _), do: {:error, :invalid_attested_credential_data}

  @spec cbor_decode_binary_unknown_length(binary, non_neg_integer(), non_neg_integer())
    :: {any(), non_neg_integer()}

  defp cbor_decode_binary_unknown_length(_bin, nb, max) when nb > max do
    raise "#{__MODULE__}: invalid CBOR decode error"
  end

  defp cbor_decode_binary_unknown_length(bin, nb, max) do
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
