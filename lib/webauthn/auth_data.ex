defmodule Wax.AuthData do
  @enforce_keys [
    :rp_id_hash,
    :flag_user_present,
    :flag_user_verified,
    :flag_attested_credential_data,
    :flag_extension_data_included,
    :counter,
    :attested_credential_data
  ]

  defstruct [
    :rp_id_hash,
    :flag_user_present,
    :flag_user_verified,
    :flag_attested_credential_data,
    :flag_extension_data_included,
    :counter,
    :attested_credential_data,
    :extensions
  ]

  @type t :: %__MODULE__{
    rp_id_hash: binary(),
    flag_user_present: boolean(),
    flag_user_verified: boolean(),
    flag_attested_credential_data: boolean(),
    flag_extension_data_included: boolean(),
    counter: non_neg_integer(),
    attested_credential_data: any(), #FIXME
    extensions: any() #FIXME
  }

  def new(rp_id_hash, flag_user_present, flag_user_verified, flag_attested_credential_data,
          flag_extension_data_included, counter, attested_credential_data, extensions \\ nil)
  do
    %__MODULE__{
    rp_id_hash: rp_id_hash,
    flag_user_present: flag_user_present,
    flag_user_verified: flag_user_verified,
    flag_attested_credential_data: flag_attested_credential_data,
    flag_extension_data_included: flag_extension_data_included,
    counter: counter,
    attested_credential_data: attested_credential_data,
    extensions: extensions
    }
  end
end
