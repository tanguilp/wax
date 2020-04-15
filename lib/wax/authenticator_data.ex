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

  @spec decode(binary()) :: {:ok, t()} | {:error, any()}
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
  )
  do
    flag_user_present = to_bool(flag_user_present)
    flag_user_verified = to_bool(flag_user_verified)
    flag_attested_credential_data = to_bool(flag_attested_credential_data)
    flag_extension_data_included = to_bool(flag_extension_data_included)

    {maybe_attested_credential_data, remaining_bytes} =
      if flag_attested_credential_data do
         Wax.AttestedCredentialData.decode(rest)
      else
        {nil, rest}
      end

    {extensions, remaining_bytes} =
      if flag_extension_data_included do
        {:ok, extensions, remaining_bytes} = Utils.CBOR.decode(remaining_bytes)

        {extensions, remaining_bytes}
      else
        {nil, remaining_bytes}
      end

    if remaining_bytes == "" do
      {:ok, %__MODULE__{
        rp_id_hash: rp_id_hash,
        flag_user_present: flag_user_present,
        flag_user_verified: flag_user_verified,
        flag_attested_credential_data: flag_attested_credential_data,
        flag_extension_data_included: flag_extension_data_included,
        sign_count: sign_count,
        attested_credential_data: maybe_attested_credential_data,
        extensions: extensions,
        raw_bytes: authenticator_data
       }}
    else
      {:error, :authenticator_illegal_remaining_bytes}
    end
  end

  def decode(_), do: {:error, :invalid_auth_data}

  defp to_bool(0), do: false
  defp to_bool(1), do: true
end
