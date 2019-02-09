defmodule Wax do
  require Logger

  @moduledoc """
  Functions for FIDO2 registration and authentication

  ## Options
  The options are set when generating the challenge (for both registration and
  authentication). Options can be configured either globally in the configuration
  file or when generating the challenge. Some also have default values.

  Option values set during challenge generation take precedence over globally configured
  options, which takes precedence over default values.

  These options are:

  |  Option       |  Type         |  Applies to       |  Default value                | Notes |
  |:-------------:|:-------------:|-------------------|:-----------------------------:|-------|
  |`origin`|`String.t()`|<ul style="margin:0"><li>registration</li><li>authentication</li></ul>| | Mandatory. Example: `https://www.example.com` |
  |`rp_id`|`String.t()` or `:auto`|<ul style="margin:0"><li>registration</li><li>authentication</li></ul>|If set to `:auto`, automatically determined from the `origin` (set to the host) | With `:auto`, it defaults to the full host (e.g.: `www.example.com`). This option allow you to set the `rp_id` to another valid value (e.g.: `example.com`) |
  |`user_verified_required`|`boolean()`|<ul style="margin:0"><li>registration</li><li>authentication</li></ul>| `false`| |
  |`trusted_attestation_types`|`[Wax.Attestation.type()]`|<ul style="margin:0"><li>registration</li></ul>|`[:none, :basic, :uncertain, :attca, :self]`| |
  |`verify_trust_root`|`boolean()`|<ul style="margin:0"><li>registration</li></ul>|`true`| Only for `u2f` and `packed` attestation. `tpm` attestation format is always checked against metadata |

  ## FIDO2 Metadata service (MDS) configuration

  The FIDO Alliance provides with a list of metadata statements of certified authenticators.
  A metadata statement contains trust anchors (root certificates) to verify attestations.
  Wax can automatically keep this metadata up to date but needs a access token which is
  provided by the FIDO Alliance. One can request it here:
  [https://mds2.fidoalliance.org/tokens/](https://mds2.fidoalliance.org/tokens/).

  Once the token has been granted, it has to be added in the configuration file (consider
  adding it to your `*.secret.exs` files) with the `:metadata_access_token` key. The update
  frquency can be configured with the `:metadata_update_interval` key (in seconds, defaults
  to 12 hours). Example:

  `config/dev.exs`:
  ```elixir
  use Mix.Config

  config :wax,
    metadata_update_interval: 3600,
  ```

  `config/dev.secret.exs`:
  ```elixir
  use Mix.Config

  config :wax,
    metadata_access_token: "d4904acd10a36f62d7a7d33e4c9a86628a2b0eea0c3b1a6c"
  ```
  """

  @type opts :: Keyword.t()

  @type parsed_opts :: %{required(atom()) => any()}

  @spec set_opts(opts()) :: parsed_opts()

  defp set_opts(kw) do
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
        end,
      trusted_attestation_types:
      if is_list(kw[:trusted_attestation_types]) do
        kw[:trusted_attestation_types]
      else
        Application.get_env(:wax,
                            :trusted_attestation_types,
                            [:none, :basic, :uncertain, :attca, :self])
      end,
      verify_trust_root:
        if is_boolean(kw[:verify_trust_root]) do
          kw[:verify_trust_root]
        else
          Application.get_env(:wax, :verify_trust_root, true)
        end
    }
  end

  @doc """
  Generates a new challenge for registration

  The returned structure:
  - Contains the challenge bytes under the `bytes` key (e.g.: `challenge.bytes`). This is a
  random value that must be used by the javascript WebAuthn call
  - Must be passed backed to `register/3`

  Typically, this structure is stored in the session (cookie...) for the time the WebAuthn
  process is performed on the client side.

  ## Example:
  ```elixir
  iex> Wax.new_registration_challenge("Georges", [trusted_attestation_types: [:basic, :attca]])
  %Wax.Challenge{
    allow_credentials: [],
    bytes: <<107, 108, 196, 138, 218, 172, 248, 168, 167, 89, 174, 213, 32, 60,
      236, 116, 180, 47, 11, 3, 233, 16, 210, 225, 146, 231, 219, 168, 251, 51,
      228, 224>>,
    exp: nil,
    origin: "http://localhost:4000",
    rp_id: "localhost",
    token_binding_status: nil,
    trusted_attestation_types: [:basic, :attca],
    user: "Georges",
    user_verified_required: false,
    verify_trust_root: true
  }
  ```
  """

  @spec new_registration_challenge(Wax.User.t(), opts()) :: Wax.Challenge.t()

  def new_registration_challenge(user, opts) do
    opts = set_opts(opts)

    Wax.Challenge.new(user, opts)
  end

  @spec register(binary(), Wax.ClientData.raw_string(), Wax.Challenge.t())
  :: {:ok, {Wax.CoseKey.t(), Wax.Attestation.result()}} | {:error, atom()}

  def register(attestation_object_cbor, client_data_json_raw, challenge) do

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
         {:ok, attestation_result_data}
           <- valid_attestation_statement_format?.(att_stmt,
                                                   auth_data,
                                                   client_data_hash,
                                                   challenge.verify_trust_root),
         :ok <- attestation_trustworthy?(attestation_result_data, challenge)
    do
      {:ok, {
        auth_data.attested_credential_data.credential_public_key,
        attestation_result_data
      }}
    else
      error ->
        error
    end
  end

  @spec new_authentication_challenge(Wax.User.t(), [{Wax.CredentialId.t(), Wax.CoseKey.t()}], opts())
    :: Wax.Challenge.t()

  def new_authentication_challenge(user, allow_credentials, opts) do
    opts = set_opts(opts)

    Wax.Challenge.new(user,allow_credentials, opts)
  end

  @spec authenticate(Wax.CredentialId.t(),
                     binary(),
                     binary(),
                     Wax.ClientData.raw_string(),
                     Wax.Challenge.t()
  ) :: {:ok, non_neg_integer()} | {:error, any()}

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

  @spec type_get?(Wax.ClientData.t()) :: :ok | {:error, atom()}

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
      Logger.debug("#{__MODULE__}: decoded attestation object: " <>
        "#{inspect(:cbor.decode(cbor), pretty: true)}")
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
    if !challenge.user_verified_required or auth_data.flag_user_verified do
      :ok
    else
      {:error, :user_not_verified}
    end
  end

  @spec attestation_trustworthy?(Wax.Attestation.result(), Wax.Challenge.t())
    :: :ok | {:error, any()}

  defp attestation_trustworthy?({type, _, _}, %Wax.Challenge{trusted_attestation_types: tatl})
    when is_list(tatl)
  do
    if type in tatl do
      :ok
    else
      {:error, :untrusted_attestation_type}
    end
  end

  defp attestation_trustworthy?(attestation_result,
                                %Wax.Challenge{trusted_attestation_types: tatf})
    when is_function(tatf, 1)
  do
    if tatf.(attestation_result) do
      :ok
    else
      {:error, :untrusted_attestation_type}
    end
  end

  @spec cose_key_from_credential_id(Wax.CredentialId.t(), Wax.Challenge.t())
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
