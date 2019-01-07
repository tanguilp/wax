defmodule Wax do
  require Logger

  @type client_data :: map()

  def test(attestation_obj, client_data, challenge) do
    register_new_credential(Base.decode64!(attestation_obj), client_data, challenge)
  end

  @spec new_credential_challenge(Wax.User.t()) :: Wax.AttestationChallenge.t()
  def new_credential_challenge(user) do
    Wax.AttestationChallenge.new(user)
  end

  def register_new_credential(attestation_object_cbor, client_data_json_raw, challenge) do

    with {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_create?(client_data),
         :ok <- valid_challenge?(challenge, client_data),
         :ok <- valid_origin?(client_data),
         :ok <- valid_token_binding_status?(client_data),
         client_data_hash <- :crypto.hash(:sha256, client_data_json_raw),
         {:ok, %{"fmt" => fmt, "authData" => auth_data_bin, "attStmt" => att_stmt}}
           <- cbor_decode(attestation_object_cbor),
         {:ok, auth_data} <- decode_auth_data(auth_data_bin),
         :ok <- valid_rp_id?(auth_data),
         :ok <- user_present_flag_set?(auth_data),
         :ok <- maybe_user_verified_flag_set?(auth_data),
         #FIXME: verify extensions
         {:ok, valid_attestation_statement_format?}
           <- Wax.Attestation.statement_verify_fun(fmt),
         {:ok, {attestation_type, trust_path}}
           <- valid_attestation_statement_format?.(att_stmt, auth_data, client_data_hash),
         # trust anchors are obtained by another process
         :ok <- attestation_trustworthy?(auth_data, attestation_type, trust_path),
         :ok <- credential_id_not_registered?(auth_data),
         :ok <- register_credential(auth_data, challenge)
    do
      :okidoki
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :json_decode_error}

      x ->
        x
    end
  end

  @spec authentication_challenge(Wax.User.t()) :: Wax.Challenge.t()

  def authentication_challenge(user) do
    Wax.AuthenticationChallenge.new(user)
  end

  def auth_test(credential_id, auth_data, sig, client_data, challenge) do
    authenticate(
      Base.url_decode64!(credential_id, padding: false),
      Base.decode64!(auth_data),
      Base.decode64!(sig),
      client_data,
      challenge
    )
  end

  def authenticate(credential_id,
                   auth_data_bin,
                   sig,
                   client_data_json_raw,
                   challenge) do
    user = "user_001"

    with :ok <- verify_credential_id(credential_id, challenge),
         :ok <- credential_id_of_user?(credential_id, challenge),
         {:ok, auth_data} <- Wax.AuthData.decode(auth_data_bin),
         {:ok, public_key} <- public_key_of_credential_id(challenge, credential_id),
         {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_get?(client_data),
         :ok <- valid_challenge?(challenge, client_data),                                     #8
         :ok <- valid_origin?(client_data),                                                   #9
         :ok <- valid_token_binding_status?(client_data),                                     #10
         :ok <- valid_rp_id?(auth_data),                                                      #11
         :ok <- user_present_flag_set?(auth_data),                                            #12
         :ok <- maybe_user_verified_flag_set?(auth_data),                                     #13
         #FIXME: verify extensions                                                            #14
         client_data_hash <- :crypto.hash(:sha256, client_data_json_raw),                     #15
         :ok <- valid_signature?(auth_data_bin <> client_data_hash, sig, public_key),        #16
         :ok <- handle_sig_count(auth_data)                                                   #17
    do
      :ok
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :json_decode_error}

      x ->
        x
    end
  end

  @spec type_create?(Wax.ClientData.t()) :: :ok | {:error, atom()}
  defp type_create?(client_data) do
    if client_data.type == :create do
      :ok
    else
      {:error, :attestation_invalid_type}
    end
  end

  @spec type_get?(client_data) :: :ok | {:error, atom()}
  defp type_get?(client_data) do
    if client_data.type == :get do
      :ok
    else
      {:error, :attestation_invalid_type}
    end
  end

  @spec valid_challenge?(AttestationChallenge.t() | AuthenticationChallenge.t(),
    Wax.ClientData.t()) :: :ok | {:error, any()}
  def valid_challenge?(challenge, client_data) do
    IO.inspect(client_data)
    if challenge.bytes == client_data.challenge do
      :ok
    else
      {:error, :invalid_challenge}
    end
  end

  @spec valid_origin?(Wax.ClientData.t()) :: :ok | {:error, atom()}
  defp valid_origin?(client_data) do
    if client_data.origin == "http://localhost:4000" do
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
  defp register_credential(auth_data, challenge) do
    Wax.CredentialStore.ETS.register(challenge.user,
                                     auth_data.attested_credential_data.credential_id,
                                     auth_data.attested_credential_data.credential_public_key)
  end

  defp verify_credential_id(credential_id, challenge) do
    if credential_id in challenge.allow_credentials do
      :ok
    else
      {:error, :incorrect_credential_id_for_user}
    end
  end

  defp credential_id_of_user?(credential_id, challenge) do
    :ok
  end

  defp public_key_of_credential_id(challenge, credential_id) do
    Wax.CredentialStore.ETS.get_key(challenge.user, credential_id)
  end

  defp valid_signature?(msg, sig, cose_key) do
    IO.inspect(msg)
    IO.inspect(sig)
    IO.inspect(cose_key)
    IO.inspect(Wax.CoseKey.pretty_print(cose_key))

    ecp = {:ECPoint, <<4>> <> cose_key[-2] <> cose_key[-3]}

    if :public_key.verify(msg, :sha256, sig, {ecp, {:namedCurve, :secp256r1}}) do
      :yyyeeeeeaaaahhhhhhhhhhhhhhhh
    else
      {:error, :invalid_signature}
    end
  end

  defp handle_sig_count(auth_data) do
    :ok
  end
end
