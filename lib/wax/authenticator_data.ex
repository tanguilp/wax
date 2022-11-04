defmodule Wax.AuthenticatorData do
  alias Wax.Utils

  @enforce_keys [
    :rp_id_hash,
    :flag_user_present,
    :flag_user_verified,
    :flag_attested_credential_data,
    :flag_extension_data_included,
    :sign_count,
    :attested_credential_data,
    :raw_bytes
  ]

  defstruct [
    :rp_id_hash,
    :flag_user_present,
    :flag_user_verified,
    :flag_attested_credential_data,
    :flag_extension_data_included,
    :sign_count,
    :attested_credential_data,
    :extensions,
    :raw_bytes
  ]

  @type t :: %__MODULE__{
          rp_id_hash: binary(),
          flag_user_present: boolean(),
          flag_user_verified: boolean(),
          flag_attested_credential_data: boolean(),
          flag_extension_data_included: boolean(),
          sign_count: non_neg_integer(),
          attested_credential_data: Wax.AttestedCredentialData.t(),
          extensions: map(),
          raw_bytes: binary()
        }

  @type credential_id :: binary()

  @doc """
  Returns the AAGUID of the authenticator

  Note that FIDO-U2F authenticators don't have an AAGUID, so `nil` is returned in
  this case
  """
  @spec get_aaguid(t()) :: binary() | nil
  def get_aaguid(authenticator_data) do
    case authenticator_data.attested_credential_data.aaguid do
      <<0::128>> ->
        nil

      aaguid ->
        aaguid
    end
  end

  @doc false
  @spec decode(binary()) :: {:ok, t()} | {:error, Exception.t()}
  def decode(
        <<
          rp_id_hash::binary-size(32),
          flag_extension_data_included::size(1),
          flag_attested_credential_data::size(1),
          _::size(3),
          flag_user_verified::size(1),
          _::size(1),
          flag_user_present::size(1),
          sign_count::unsigned-big-integer-size(32),
          rest::binary
        >> = authenticator_data
      ) do
    flag_user_present = to_bool(flag_user_present)
    flag_user_verified = to_bool(flag_user_verified)
    flag_attested_credential_data = to_bool(flag_attested_credential_data)
    flag_extension_data_included = to_bool(flag_extension_data_included)

    with {:ok, {maybe_attested_credential_data, remaining_bytes}} <-
           attested_credential_data(rest, flag_attested_credential_data),
         {:ok, maybe_extensions, remaining_bytes} <-
           extensions(remaining_bytes, flag_extension_data_included),
         :ok <- check_no_remaining_bytes(remaining_bytes) do
      {:ok,
       %__MODULE__{
         rp_id_hash: rp_id_hash,
         flag_user_present: flag_user_present,
         flag_user_verified: flag_user_verified,
         flag_attested_credential_data: flag_attested_credential_data,
         flag_extension_data_included: flag_extension_data_included,
         sign_count: sign_count,
         attested_credential_data: maybe_attested_credential_data,
         extensions: maybe_extensions,
         raw_bytes: authenticator_data
       }}
    end
  end

  def decode(_), do: {:error, %Wax.InvalidAuthenticatorDataError{}}

  defp attested_credential_data(bytes, true), do: Wax.AttestedCredentialData.decode(bytes)
  defp attested_credential_data(bytes, false), do: {:ok, {nil, bytes}}

  defp extensions(bytes, true), do: Utils.CBOR.decode(bytes)
  defp extensions(bytes, false), do: {:ok, nil, bytes}

  defp check_no_remaining_bytes(""), do: :ok
  defp check_no_remaining_bytes(_), do: {:error, %Wax.InvalidAuthenticatorDataError{}}

  defp to_bool(0), do: false
  defp to_bool(1), do: true
end
