defmodule Wax do
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
  |`attestation`|`"none"` or `"direct"`|<ul style="margin:0"><li>registration</li></ul>| `"none"` | |
  |`origin`|`String.t()`|<ul style="margin:0"><li>registration</li><li>authentication</li></ul>| | **Mandatory**. Example: `https://www.example.com` |
  |`rp_id`|`String.t()` or `:auto`|<ul style="margin:0"><li>registration</li><li>authentication</li></ul>|If set to `:auto`, automatically determined from the `origin` (set to the host) | With `:auto`, it defaults to the full host (e.g.: `www.example.com`). This option allow you to set the `rp_id` to another valid value (e.g.: `example.com`) |
  |`user_verification`|`"discouraged"`, `"preferred"` or `"required"`|<ul style="margin:0"><li>registration</li><li>authentication</li></ul>| `"preferred"`| |
  |`trusted_attestation_types`|`[Wax.Attestation.type()]`|<ul style="margin:0"><li>registration</li></ul>|`[:none, :basic, :uncertain, :attca, :self]`| |
  |`verify_trust_root`|`boolean()`|<ul style="margin:0"><li>registration</li></ul>|`true`| Only for `u2f` and `packed` attestation. `tpm` attestation format is always checked against metadata |
  |`acceptable_authenticator_statuses`|`[Wax.Metadata.TOCEntry.StatusReport.status()]`|<ul style="margin:0"><li>registration</li></ul>|`[:fido_certified, :fido_certified_l1, :fido_certified_l1plus, :fido_certified_l2, :fido_certified_l2plus, :fido_certified_l3, :fido_certified_l3plus]`| The `:update_available` status is not whitelisted by default |
  |`timeout`|`non_neg_integer()`|<ul style="margin:0"><li>registration</li><li>authentication</li></ul>|`20 * 60`| The validity duration of a challenge |
  |`android_key_allow_software_enforcement`|`boolean()`|<ul style="margin:0"><li>registration</li></ul>|`false`| When registration is a Android key, determines whether software enforcement is acceptable (`true`) or only hardware enforcement is (`false`) |
  |`silent_authentication_enabled`|`boolean()`|<ul style="margin:0"><li>authentication</li></ul>|`false`| See [https://github.com/fido-alliance/conformance-tools-issues/issues/434](https://github.com/fido-alliance/conformance-tools-issues/issues/434) |

  ## FIDO2 Metadata service (MDS) configuration

  The FIDO Alliance provides with a list of metadata statements of certified **FIDO2**
  authenticators. A metadata statement contains trust anchors (root certificates) to verify
  attestations. Wax can automatically keep this metadata up to date but needs a access token which
  is provided by the FIDO Alliance. One can request it here:
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

  Note that some **FIDO1** certififed authenticators, such as Yubikeys, won't be present in this
  list and Wax doesn't load data from the former ("FIDO1") metadata Web Service. The FIDO
  Alliance plans to provides with a web service having both FIDO1 and FIDO2, but there is no
  roadmap as of September 2019.

  During the registration process, when trust root is verified against FIDO2 metadata, only
  metadata entries whose last status is whitelisted by the `:acceptable_authenticator_statuses`
  will be used. Otherwise a warning is logged and the registration process fails. Metadata is still
  loaded for debugging purpose in the `:wax_metadata` ETS table.

  ## Loading FIDO2 metadata from a directory

  In addition to the FIDO2 metadata service, it is possible to load metadata from a directory.
  To do so, the `:metadata_dir` application environment variable must be set to one of:
  - a `String.t()`: the path to the directory containing the metadata files
  - an `atom()`: in this case, the files are loaded from the `"fido2_metadata"` directory of the
  private (`"priv/"`) directory of the application (whose name is the atom)

  In both case, Wax tries to load all files (even directories and other special files).

  ### Example configuration

  ```elixir
  config :wax,
    origin: "http://localhost:4000",
    rp_id: :auto,
    metadata_dir: :my_application
  ```

  will try to load all files of the `"priv/fido2_metadata/"` if the `:my_application` as FIDO2
  metadata statements. On failure, a warning is emitted.
  """

  require Logger

  alias Wax.Utils

  @type opts :: [opt()]

  @type opt ::
  {:attestation, String.t()}
  | {:origin, String.t()}
  | {:rp_id, String.t() | :auto}
  | {:user_verification, String.t()}
  | {:trusted_attestation_types, [Wax.Attestation.type()]}
  | {:verify_trust_root, boolean()}
  | {:acceptable_authenticator_statuses, [Wax.Metadata.TOCEntry.StatusReport.status()]}
  | {:issued_at, integer()}
  | {:timeout, non_neg_integer()}
  | {:android_key_allow_software_enforcement, boolean()}
  | {:silent_authentication_enabled, boolean()}

  @spec set_opts(opts()) :: opts()
  defp set_opts(opts) do
    attestation =
      case opts[:attestation] do
        "none" -> "none"
        nil -> "none"
        "direct" -> "direct"
        _ -> raise "Invalid attestation, must be one of: `\"none\"`, `\"direct\"`"
      end

    origin =
      if is_binary(opts[:origin]) do
        opts[:origin]
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
      if opts[:rp_id] == :auto or Application.get_env(:wax, :rp_id) == :auto do
        URI.parse(origin).host
      else
        if is_binary(opts[:rp_id]) do
          opts[:rp_id]
        else
          case Application.get_env(:wax, :rp_id) do
            rp_id when is_binary(rp_id) ->
              rp_id

            _ ->
              raise "Missing mandatory parameter `rp_id` (String.t())"
          end
        end
      end

    if opts[:user_verification] &&
      opts[:user_verification] not in ["discouraged", "preferred", "required"] do
      raise "Invalid `:user_verification` parameter, must be one of: " <>
        "\"discouraged\", \"preferred\", \"required\""
    end

    [
      type: opts[:type],
      attestation: attestation,
      origin: origin,
      rp_id: rp_id,
      user_verification:
        opts[:user_verification]
        || Application.get_env(:wax, :user_verification, "preferred"),
      trusted_attestation_types:
        opts[:trusted_attestation_types] || Application.get_env(
          :wax,
          :trusted_attestation_types,
          [:none, :basic, :uncertain, :attca, :self]
        ),
      verify_trust_root:
        opts[:verify_trust_root] || Application.get_env(:wax, :verify_trust_root, true),
      acceptable_authenticator_statuses:
        opts[:acceptable_authenticator_statuses] || Application.get_env(
          :wax,
          :acceptable_authenticator_statuses,
          [
            :fido_certified,
            :fido_certified_l1,
            :fido_certified_l1plus,
            :fido_certified_l2,
            :fido_certified_l2plus,
            :fido_certified_l3,
            :fido_certified_l3plus
          ]
        ),
      issued_at: :erlang.monotonic_time(:second),
      timeout: opts[:timeout] || Application.get_env(:wax, :timeout, 60 * 20),
      android_key_allow_software_enforcement:
        opts[:android_key_allow_software_enforcement]
        || Application.get_env(:wax, :android_key_allow_software_enforcement)
        || false,
      silent_authentication_enabled:
        opts[:silent_authentication_enabled]
        || Application.get_env(:wax, :silent_authentication_enabled, false)
    ]
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
  iex> Wax.new_registration_challenge(trusted_attestation_types: [:basic, :attca])
  %Wax.Challenge{
    allow_credentials: [],
    bytes: <<192, 64, 240, 166, 163, 188, 76, 255, 108, 227, 18, 33, 123, 19, 61,
      3, 166, 195, 190, 157, 24, 207, 210, 179, 180, 136, 10, 135, 82, 172, 134,
      17>>,
    origin: "http://localhost:4000",
    rp_id: "localhost",
    token_binding_status: nil,
    trusted_attestation_types: [:basic, :attca],
    user_verification: "preferred",
    verify_trust_root: true
  }
  ```
  """

  @spec new_registration_challenge(opts()) :: Wax.Challenge.t()

  def new_registration_challenge(opts) do
    opts = set_opts(Keyword.put(opts, :type, :attestation))

    Wax.Challenge.new(opts)
  end

  @doc """
  Verifies a registration response from the client WebAuthn javascript call

  The input params are:
  - `attestation_object_cbor`: the **raw binary** response from the WebAuthn javascript API.
  When transmitting it back from the browser to the server, it will probably be base64
  encoded. Make sure to decode it before.
  - `client_data_json_raw`: the JSON string (and **not** the decoded JSON) of the client data
  JSON as returned by the WebAuthn javascript API
  - `challenge`: the challenge that was generated beforehand, and whose bytes has been sent
  to the browser and used as an input by the WebAuthn javascript API

  The success return value is of the form:
  `{authenticator_data, {attestation_type, trust_path, metadata_statement}}`.
  One can access the credential public key i nthe authenticator data structure:

  ```elixir
  auth_data.attested_credential_data.credential_public_key
  ```

  Regarding the attestation processes' result, see `t:Wax.Attestation.result/0` for more
  details. Note, however, that you can use
  the returned metadata statement (if any) to further check the authenticator capabilites.
  For example, the following conditions will only allow attestation generated by
  hardware protected attestation keys:

  ```elixir
  case Wax.register(attestation_object, client_data_json_raw, challenge) do
    {:ok, {authenticator_data, {_, _, metadata_statement}}} ->
      # tee is for "trusted execution platform"
      if :key_protection_tee in metadata_statement.key_protection or
         :key_protection_secure_element in metadata_statement.key_protection
      do
        register_key(user, credential_id, authenticator_data.attested_credential_data.cose_key)

        :ok
      else
        {:error, :not_hardware_protected}
      end

    {:error, _} = error ->
      error
  end
  ```

  When performing registration, the server has the 3 following pieces of data:
  - user id: specific to the server implementation. Can be a email, login name, or an opaque
  user identifier
  - credential id: an ID returned by the WebAuthn javascript. It is a handle to further
  authenticate the user. It is also available in the authenticator data in binary form, and
  can be accessed by typing: `auth_data.attested_credential_data.credential_id`
  - the COSE key: available in the authenticator data
  (`auth_data.attested_credential_data.credential_public_key`)  under the form of a map
  containing a public key use for further authentication

  A credential id is related to a cose key, and vice-versa.

  Note that a user can have several (credential id, cose key) pairs, for example if the
  user uses different authenticators. The unique key (for storage, etc.) is therefore the tuple
  (user id, credential id).

  In the success case, and after calling `register/3`, a server shall:
  1. Verify that no other user has the same credential id (and should fail otherwise)
  2. Store the new tuple (credential id, cose key) for the user
  """

  @spec register(binary(), Wax.ClientData.raw_string(), Wax.Challenge.t())
  :: {:ok, {Wax.AuthenticatorData.t(), Wax.Attestation.result()}} | {:error, atom()}

  def register(attestation_object_cbor, client_data_json_raw, challenge) do

    with :ok <- not_expired?(challenge),
         {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_create?(client_data),
         :ok <- valid_challenge?(client_data, challenge),
         :ok <- valid_origin?(client_data, challenge),
         client_data_hash = :crypto.hash(:sha256, client_data_json_raw),
         {:ok, att_data, _} <- Utils.CBOR.decode(attestation_object_cbor),
         %{"fmt" => fmt, "authData" => auth_data_bin, "attStmt" => att_stmt} = att_data,
         {:ok, auth_data} <- Wax.AuthenticatorData.decode(auth_data_bin),
         :ok <- valid_rp_id?(auth_data, challenge),
         :ok <- user_present_flag_set?(auth_data, challenge),
         :ok <- maybe_user_verified_flag_set?(auth_data, challenge),
         {:ok, valid_attestation_statement_format?}
           <- Wax.Attestation.statement_verify_fun(fmt),
         {:ok, attestation_result_data} <- valid_attestation_statement_format?.(
           att_stmt,
           auth_data,
           client_data_hash,
           challenge
         ),
         :ok <- attestation_trustworthy?(attestation_result_data, challenge)
    do
      {:ok, {auth_data, attestation_result_data}}
    end
  end

  @doc """
  Generates a new challenge for authentication

  The first argument is a list of (credential id, cose key) which were previsouly
  registered (after successful `register/3`) for a user. This can be retrieved from
  a user database for instance.

  The returned structure:
  - Contains the challenge bytes under the `bytes` key (e.g.: `challenge.bytes`). This is a
  random value that must be used by the javascript WebAuthn call
  - Must be passed backed to `authenticate/5`

  Typically, this structure is stored in the session (cookie...) for the time the WebAuthn
  authentication process is performed on the client side.

  ## Example:
  ```elixir
  iex> cred_ids_and_associated_keys = UserDatabase.load_cred_id("Georges")
  [
    {"vwoRFklWfHJe1Fqjv7wY6exTyh23PjIBC4tTc4meXCeZQFEMwYorp3uYToGo8rVwxoU7c+C8eFuFOuF+unJQ8g==",
     %{
       -3 => <<121, 21, 84, 106, 84, 48, 91, 21, 161, 78, 176, 199, 224, 86, 196,
         226, 116, 207, 221, 200, 26, 202, 214, 78, 95, 112, 140, 236, 190, 183,
         177, 223>>,
       -2 => <<195, 105, 55, 252, 13, 134, 94, 208, 83, 115, 8, 235, 190, 173,
         107, 78, 247, 125, 65, 216, 252, 232, 41, 13, 39, 104, 231, 65, 200, 149,
         172, 118>>,
       -1 => 1,
       1 => 2,
       3 => -7
     }},
    {"E0YtUWEPcRLyW1wd4v3KuHqlW1DRQmF2VgNhhR1FumtMYPUEu/d3RO+WC4T4XIa0PZ6Pjw+IBNQDn/It5UjWmw==",
     %{
       -3 => <<113, 34, 76, 107, 120, 21, 246, 189, 21, 167, 119, 39, 245, 140,
         143, 133, 209, 19, 63, 196, 145, 52, 43, 2, 193, 208, 200, 103, 3, 51,
         37, 123>>,
       -2 => <<199, 68, 146, 57, 216, 62, 11, 98, 8, 108, 9, 229, 40, 97, 201,
         127, 47, 240, 50, 126, 138, 205, 37, 148, 172, 240, 65, 125, 70, 81, 213,
         152>>,
       -1 => 1,
       1 => 2,
       3 => -7
     }}
  ]
  iex> Wax.new_authentication_challenge(cred_ids_and_associated_keys, [])
  %Wax.Challenge{
    allow_credentials: [
      {"vwoRFklWfHJe1Fqjv7wY6exTyh23PjIBC4tTc4meXCeZQFEMwYorp3uYToGo8rVwxoU7c+C8eFuFOuF+unJQ8g==",
       %{
         -3 => <<121, 21, 84, 106, 84, 48, 91, 21, 161, 78, 176, 199, 224, 86,
           196, 226, 116, 207, 221, 200, 26, 202, 214, 78, 95, 112, 140, 236, 190,
           183, 177, 223>>,
         -2 => <<195, 105, 55, 252, 13, 134, 94, 208, 83, 115, 8, 235, 190, 173,
           107, 78, 247, 125, 65, 216, 252, 232, 41, 13, 39, 104, 231, 65, 200,
           149, 172, 118>>,
         -1 => 1,
         1 => 2,
         3 => -7
       }},
      {"E0YtUWEPcRLyW1wd4v3KuHqlW1DRQmF2VgNhhR1FumtMYPUEu/d3RO+WC4T4XIa0PZ6Pjw+IBNQDn/It5UjWmw==",
       %{
         -3 => <<113, 34, 76, 107, 120, 21, 246, 189, 21, 167, 119, 39, 245, 140,
           143, 133, 209, 19, 63, 196, 145, 52, 43, 2, 193, 208, 200, 103, 3, 51,
           37, 123>>,
         -2 => <<199, 68, 146, 57, 216, 62, 11, 98, 8, 108, 9, 229, 40, 97, 201,
           127, 47, 240, 50, 126, 138, 205, 37, 148, 172, 240, 65, 125, 70, 81,
           213, 152>>,
         -1 => 1,
         1 => 2,
         3 => -7
       }}
    ],
    bytes: <<130, 70, 153, 38, 189, 145, 193, 3, 132, 158, 170, 216, 8, 93, 221,
      46, 206, 156, 104, 24, 78, 167, 182, 5, 6, 128, 194, 201, 196, 246, 243,
      194>>,
    exp: nil,
    origin: "http://localhost:4000",
    rp_id: "localhost",
    token_binding_status: nil,
    trusted_attestation_types: [:none, :basic, :uncertain, :attca, :self],
    user_verification: "preferred",
    verify_trust_root: true
  }
  ```
  """

  @spec new_authentication_challenge([{Wax.CredentialId.t(), Wax.CoseKey.t()}], opts())
    :: Wax.Challenge.t()

  def new_authentication_challenge(allow_credentials, opts) do
    opts = set_opts(Keyword.put(opts, :type, :authentication))

    Wax.Challenge.new(allow_credentials, opts)
  end

  @doc """
  Verifies a authentication response from the client WebAuthn javascript call

  The input params are:
  - `credential_id`: the credential id returned by the WebAuthn javascript API. Must be of
  the same form as the one passed to `new_authentication_challenge/2` as it will be
  compared against the previously retrieved valid credential ids
  - `auth_data_bin`: the authenticator data returned by the WebAuthn javascript API. Must
  be the raw binary, not the base64 encoded form
  - `sig`: the signature returned by the WebAuthn javascript API. Must
  be the raw binary, not the base64 encoded form
  - `client_data_json_raw`: the JSON string (and **not** the decoded JSON) of the client data
  JSON as returned by the WebAuthn javascript API
  - `challenge`: the challenge that was generated beforehand, and whose bytes has been sent
  to the browser and used as an input by the WebAuthn javascript API

  The call returns `{:ok, authenticator_data}` in case of success, or `{:error, :reason}`
  otherwise.

  The `auth_data.sign_count` is the number of signature performed by this authenticator for this
  credential id, and can be used to detect cloning of authenticator. See point 17 of the
  [7.2. Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-1/#verifying-assertion)
  for more details.
  """
  @spec authenticate(Wax.CredentialId.t(),
                     binary(),
                     binary(),
                     Wax.ClientData.raw_string(),
                     Wax.Challenge.t()
  ) :: {:ok, Wax.AuthenticatorData.t()} | {:error, atom()}

  def authenticate(credential_id,
                   auth_data_bin,
                   sig,
                   client_data_json_raw,
                   challenge)
  do
    with :ok <- not_expired?(challenge),
         {:ok, cose_key} <- cose_key_from_credential_id(credential_id, challenge),
         {:ok, auth_data} <- Wax.AuthenticatorData.decode(auth_data_bin),
         {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_get?(client_data),
         :ok <- valid_challenge?(client_data, challenge),
         :ok <- valid_origin?(client_data, challenge),
         :ok <- valid_rp_id?(auth_data, challenge),
         :ok <- user_present_flag_set?(auth_data, challenge),
         :ok <- maybe_user_verified_flag_set?(auth_data, challenge),
         client_data_hash = :crypto.hash(:sha256, client_data_json_raw),
         :ok <- Wax.CoseKey.verify(auth_data_bin <> client_data_hash, cose_key, sig)
    do
      {:ok, auth_data}
    end
  end

  @spec not_expired?(Wax.Challenge.t()) :: :ok | {:error, :challenge_expired}
  defp not_expired?(%Wax.Challenge{issued_at: issued_at, timeout: timeout}) do
    current_time = :erlang.monotonic_time(:second)

    if current_time - issued_at < timeout do
      :ok
    else
      {:error, :challenge_expired}
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

  defp valid_challenge?(client_data, challenge) do
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

  @spec valid_rp_id?(Wax.AuthenticatorData.t(), Wax.Challenge.t()) :: :ok | {:error, atom()}
  defp valid_rp_id?(auth_data, challenge) do
    if auth_data.rp_id_hash == :crypto.hash(:sha256, challenge.rp_id) do
      :ok
    else
      {:error, :invalid_rp_id}
    end
  end

  @spec user_present_flag_set?(
    Wax.AuthenticatorData.t(),
    Wax.Challenge.t()
  ) :: :ok | {:error, any()}
  defp user_present_flag_set?(
    _auth_data,
    %Wax.Challenge{type: :authentication, silent_authentication_enabled: true})
  do
    :ok
  end

  defp user_present_flag_set?(auth_data, _challenge) do
    if auth_data.flag_user_present == true do
      :ok
    else
      {:error, :flag_user_present_not_set}
    end
  end

  @spec maybe_user_verified_flag_set?(Wax.AuthenticatorData.t(), Wax.Challenge.t())
    :: :ok | {:error, atom()}
  defp maybe_user_verified_flag_set?(auth_data, challenge) do
    case challenge.user_verification do
      "required" ->
        if auth_data.flag_user_verified do
          :ok
        else
          {:error, :user_not_verified}
        end

      _ ->
        :ok
    end
  end

  @spec attestation_trustworthy?(Wax.Attestation.result(), Wax.Challenge.t())
    :: :ok | {:error, any()}

  defp attestation_trustworthy?({type, _, _}, %Wax.Challenge{trusted_attestation_types: tatl})
  do
    if type in tatl do
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
