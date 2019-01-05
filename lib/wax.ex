defmodule Wax do
  require Logger

  @type client_data :: map()

  def test() do
    rawid = "AN6ERG4dqtOjaeIN6139euvOVBbemRABHQIfHnUpZWN56KeGnVyMC7LfuKSQLTkwX+efIYE0AQKjrBw1JOXTnQ=="

    client_data = ~s({"challenge":"AAAAAAAAAAAAAAAAAAAAAA","clientExtensions":{},"hashAlgorithm":"SHA-256","origin":"http://localhost:4000","type":"webauthn.create"}) 

    {:ok, attestation_obj} = Base.decode64("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQADehERuHarTo2niDetd/XrrzlQW3pkQAR0CHx51KWVjeeinhp1cjAuy37ikkC05MF/nnyGBNAECo6wcNSTl052lAQIDJiABIVggJ9uN0t6HOlS8bfyTjGaGDrSrSs6v+IQAiow6zwDATugiWCCnb81bSAxn7AYwitIDhIhGGKJZi5NjLGBlIcuZFiprng==")

    register_new_credential(attestation_obj, client_data)
  end

  def test(attestation_obj, client_data) do
    register_new_credential(Base.decode64!(attestation_obj), client_data)
  end
  
  def register_new_credential(attestation_object_cbor, client_data_json_raw) do
    user = "user_001"

    with {:ok, client_data_json} <- utf8_decode_client_data_json(client_data_json_raw),       #1
         {:ok, client_data} <- Jason.decode(client_data_json),                                #2
         :ok <- type_create?(client_data),                                                    #3
         :ok <- valid_challenge?(client_data),                                                #4
         :ok <- valid_origin?(client_data),                                                   #5
         :ok <- valid_token_binding_status?(client_data),                                     #6
         client_data_hash <- :crypto.hash(:sha256, client_data_json_raw),                     #7
         {:ok, %{"fmt" => fmt, "authData" => auth_data_bin, "attStmt" => att_stmt}}           #8
           <- cbor_decode(attestation_object_cbor),
         {:ok, auth_data} <- decode_auth_data(auth_data_bin),
         :ok <- valid_rp_id?(auth_data),                                                      #9
         :ok <- user_present_flag_set?(auth_data),                                            #10
         :ok <- maybe_user_verified_flag_set?(auth_data),                                     #11
         #FIXME: verify extensions                                                            #12
         {:ok, valid_attestation_statement_format?}                                           #13
           <- Wax.Attestation.statement_verify_fun(fmt),
         {:ok, {attestation_type, trust_path}}                                                #14
           <- valid_attestation_statement_format?.(att_stmt, auth_data, client_data_hash),
         # trust anchors are obtained by another process                                      #15
         :ok <- attestation_trustworthy?(auth_data, attestation_type, trust_path),            #16
         :ok <- credential_id_not_registered?(auth_data),                                     #17
         :ok <- register_credential(user, auth_data)
    do
      :ok
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :json_decode_error}

      x ->
        x
    end
  end

  defp utf8_decode_client_data_json(client_data_json_raw) do
    #FIXME: implement https://encoding.spec.whatwg.org/#utf-8-decode ?
    {:ok, client_data_json_raw}
  end

  @spec type_create?(client_data) :: :ok | {:error, atom()}
  defp type_create?(client_data) do
    if client_data["type"] == "webauthn.create" do
      :ok
    else
      {:error, :attestation_invalid_type}
    end
  end

  @spec valid_challenge?(client_data) :: :ok | {:error, atom()}
  defp valid_challenge?(client_data) do
    #FIXME
    if client_data["challenge"] == "AAAAAAAAAAAAAAAAAAAAAA" do
      :ok
    else
      {:error, :attestation_invalid_challenge}
    end
  end

  @spec valid_origin?(client_data) :: :ok | {:error, atom()}
  defp valid_origin?(client_data) do
    if client_data["origin"] == "http://localhost:4000" do
      :ok
    else
      {:error, :attestation_invalid_origin}
    end
  end

  defp valid_token_binding_status?(client_data), do: :ok

  defp cbor_decode(cbor) do
    try do
      Logger.debug("#{__MODULE__}: decoded cbor: #{inspect(:cbor.decode(cbor), pretty: true)}")
      {:ok, :cbor.decode(cbor)}
    catch
      _ -> {:error, :invalid_cbor}
    end
  end

  defp decode_auth_data(auth_data_bin) do
    <<
      rp_id_hash::binary-size(32),
      flag_extension_data_included::size(1),
      flag_attested_credential_data::size(1),
      _::size(3),
      flag_user_verified::size(1),
      _::size(1),
      flag_user_present::size(1),
      counter::unsigned-big-integer-size(32),
      aaguid::binary-size(16),
      credential_id_length::unsigned-big-integer-size(16),
      credential_id::binary-size(credential_id_length),
      credential_public_key::binary
    >> = auth_data_bin

    attested_credential_data = Wax.AttestedCredentialData.new(aaguid,credential_id, 
      :cbor.decode(credential_public_key))

    auth_data = Wax.AuthData.new(rp_id_hash,
      (if flag_user_present == 1, do: true, else: false),
      (if flag_user_verified == 1, do: true, else: false),
      (if flag_attested_credential_data == 1, do: true, else: false),
      (if flag_extension_data_included == 1, do: true, else: false),
      counter,
      attested_credential_data)

    Logger.debug("#{__MODULE__}: decoded auth_data: #{inspect(auth_data, pretty: true)}")
    {:ok, auth_data}
  end

  @spec valid_rp_id?(Wax.AuthData.t()) :: :ok | {:error, any()}
  defp valid_rp_id?(auth_data) do
    if auth_data.rp_id_hash == :crypto.hash(:sha256, "localhost") do #FIXME
      :ok
    else
      {:error, :invalid_rp_id}
    end
  end

  @spec user_present_flag_set?(Wax.AuthData.t()) :: :ok | {:error, any()}
  defp user_present_flag_set?(auth_data) do
    if auth_data.flag_user_present == true do
      :ok
    else
      {:error, :flag_user_present_not_set}
    end
  end

  @spec maybe_user_verified_flag_set?(Wax.AuthData.t()) :: :ok | {:error, any()}
  defp maybe_user_verified_flag_set?(auth_data) do
    :ok #FIXME
  end

  defp attestation_trustworthy?(auth_data, attestation_type, trust_path) do
    :ok
  end
  defp credential_id_not_registered?(auth_data) do
    :ok
  end
  defp register_credential(user_handle, auth_data) do
    :ok
  end
end
