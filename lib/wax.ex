defmodule Wax do
  require Logger

  @type opts :: Keyword.t()

  @type parsed_opts :: %{required(atom()) => any()}

  @type credential_id :: binary()

  @spec set_opts(opts()) :: parsed_opts()
  def set_opts(kw) do
    origin =
      if is_binary(kw[:origin]) do
        kw[:origin]
      else
        case Application.get_env(:wax, :origin) do
          origin when is_binary(origin) ->
            origin

          _ ->
            raise "Missing mandatory parameter `origin` (String.t())"
        end
      end

    unless URI.parse(origin).host == "localhost" or URI.parse(origin).scheme == "https" do
      raise "Invalid origin `#{origin}` (must be either https scheme or `localhost`)"
    end

    rp_id =
      if kw[:rp_id] == :auto or Application.get_env(:wax, :rp_id) == :auto do
        URI.parse(origin).host
      else
        if is_binary(kw[:rp_id]) do
          kw[:rp_id]
        else
          case Application.get_env(:wax, :rp_id) do
            rp_id when is_binary(rp_id) ->
              rp_id

            _ ->
              raise "Missing mandatory parameter `rp_id` (String.t())"
          end
        end
      end

    %{
      origin: origin,
      rp_id: rp_id,
      user_verified_required:
        if is_boolean(kw[:user_verified_required]) do
          kw[:user_verified_required]
        else
          Application.get_env(:wax, :user_verified_required, false)
        end
    }
  end

  @type client_data :: map()

  def test(attestation_obj, client_data, challenge) do
    new_credential_verify(Base.decode64!(attestation_obj), client_data, challenge)
  end

  @spec new_credential_challenge(Wax.User.t(), opts()) :: Wax.Challenge.t()
  def new_credential_challenge(user, opts) do
    opts = set_opts(opts)

    Wax.Challenge.new(user, opts)
  end

  def new_credential_verify(attestation_object_cbor, client_data_json_raw, challenge) do

    with {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_create?(client_data),
         :ok <- valid_challenge?(client_data, challenge),
         :ok <- valid_origin?(client_data, challenge),
         :ok <- valid_token_binding_status?(client_data, challenge),
         client_data_hash <- :crypto.hash(:sha256, client_data_json_raw),
         {:ok, %{"fmt" => fmt, "authData" => auth_data_bin, "attStmt" => att_stmt}}
           <- cbor_decode(attestation_object_cbor),
         {:ok, auth_data} <- Wax.AuthenticatorData.decode(auth_data_bin),
         :ok <- valid_rp_id?(auth_data, challenge),
         :ok <- user_present_flag_set?(auth_data),
         :ok <- maybe_user_verified_flag_set?(auth_data, challenge),
         #FIXME: verify extensions
         {:ok, valid_attestation_statement_format?}
           <- Wax.Attestation.statement_verify_fun(fmt),
         {:ok, {attestation_type, trust_path}}
           <- valid_attestation_statement_format?.(att_stmt, auth_data, client_data_hash),
         :ok <- attestation_trustworthy?(auth_data, attestation_type, trust_path)
    do
      {:ok,
        {
          auth_data.attested_credential_data.credential_id,
          auth_data.attested_credential_data.credential_public_key
        }
      }
    else
      error ->
        error
    end
  end

  @spec authentication_challenge(Wax.User.t(), [{credential_id(), Wax.CoseKey.t()}], opts())
    :: Wax.Challenge.t()

  def authentication_challenge(user, allow_credentials, opts) do
    opts = set_opts(opts)

    Wax.Challenge.new(user,allow_credentials, opts)
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
    with {:ok, cose_key} <- cose_key_from_credential_id(credential_id, challenge),
         {:ok, auth_data} <- Wax.AuthenticatorData.decode(auth_data_bin),
         {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_get?(client_data),
         :ok <- valid_challenge?(client_data, challenge),
         :ok <- valid_origin?(client_data, challenge),
         :ok <- valid_token_binding_status?(client_data, challenge),
         :ok <- valid_rp_id?(auth_data, challenge),
         :ok <- user_present_flag_set?(auth_data),
         :ok <- maybe_user_verified_flag_set?(auth_data, challenge),
         #FIXME: verify extensions
         client_data_hash <- :crypto.hash(:sha256, client_data_json_raw),
         :ok <- Wax.CoseKey.verify(auth_data_bin <> client_data_hash, cose_key, sig)
    do
      {:ok, auth_data.sign_count}
    else
      error ->
        error
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

  @spec valid_challenge?(Wax.ClientData.t(), Wax.Challenge.t()) :: :ok | {:error, any()}
  def valid_challenge?(client_data, challenge) do
    if client_data.challenge == challenge.bytes do
      :ok
    else
      {:error, :invalid_challenge}
    end
  end

  @spec valid_origin?(Wax.ClientData.t(), Wax.Challenge.t()) :: :ok | {:error, atom()}
  defp valid_origin?(client_data, challenge) do
    if client_data.origin == challenge.origin do
      :ok
    else
      {:error, :attestation_invalid_origin}
    end
  end

  @spec valid_token_binding_status?(Wax.ClientData.t(), Wax.Challenge.t())
    :: :ok | {:error, atom()}
  defp valid_token_binding_status?(_client_data, _challenge), do: :ok #FIXME: implement?

  defp cbor_decode(cbor) do
    try do
      Logger.debug("#{__MODULE__}: decoded cbor: #{inspect(:cbor.decode(cbor), pretty: true)}")
      {:ok, :cbor.decode(cbor)}
    catch
      _ -> {:error, :invalid_cbor}
    end
  end

  @spec valid_rp_id?(Wax.AuthenticatorData.t(), Wax.Challenge.t()) :: :ok | {:error, atom()}
  defp valid_rp_id?(auth_data, challenge) do
    if auth_data.rp_id_hash == :crypto.hash(:sha256, challenge.rp_id) do
      :ok
    else
      {:error, :invalid_rp_id}
    end
  end

  @spec user_present_flag_set?(Wax.AuthenticatorData.t()) :: :ok | {:error, any()}
  defp user_present_flag_set?(auth_data) do
    if auth_data.flag_user_present == true do
      :ok
    else
      {:error, :flag_user_present_not_set}
    end
  end

  @spec maybe_user_verified_flag_set?(Wax.AuthenticatorData.t(), Wax.Challenge.t())
    :: :ok | {:error, atom()}
  defp maybe_user_verified_flag_set?(auth_data, challenge) do
    if not challenge.user_verified_required or auth_data.flag_user_verified do
      :ok
    else
      {:error, :user_not_verified}
    end
  end

  defp attestation_trustworthy?(_auth_data, _attestation_type, _trust_path) do
    :ok #FIXME: implement policy
  end

  @spec cose_key_from_credential_id(credential_id(), Wax.Challenge.t())
    :: {:ok, Wax.CoseKey.t()} | {:error, any()}
  defp cose_key_from_credential_id(credential_id, challenge) do
    case List.keyfind(challenge.allow_credentials, credential_id, 0) do
      {_, cose_key} ->
        {:ok, cose_key}

      _ ->
        {:error, :incorrect_credential_id_for_user}
    end
  end
end
