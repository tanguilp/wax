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
  |`attestation`|`"none"` or `"direct"`|registration|`"none"`| |
  |`origin`|`String.t()`|registration & authentication| | **Mandatory**. Example: `https://www.example.com` |
  |`rp_id`|`String.t()` or `:auto`|registration & authentication|If set to `:auto`, automatically determined from the `origin` (set to the host) | With `:auto`, it defaults to the full host (e.g.: `www.example.com`). This option allow you to set the `rp_id` to another valid value (e.g.: `example.com`) |
  |`user_verification`|`"discouraged"`, `"preferred"` or `"required"`|registration & authentication|`"preferred"`| |
  |`allow_credentials`|`[{Wax.AuthenticatorData.credential_id(), Wax.CoseKey.t()}]`|authentication|`[]`| |
  |`trusted_attestation_types`|`[t:Wax.Attestation.type/0]`|registration|`[:none, :basic, :uncertain, :attca, :anonca, :self]`| |
  |`verify_trust_root`|`boolean()`|registration|`true`|Only for `u2f` and `packed` attestation. `tpm` attestation format is always checked against metadata|
  |`acceptable_authenticator_statuses`|`[String.t()]`|registration|`["FIDO_CERTIFIED", "FIDO_CERTIFIED_L1",  "FIDO_CERTIFIED_L1plus", "FIDO_CERTIFIED_L2", "FIDO_CERTIFIED_L2plus", "FIDO_CERTIFIED_L3", "FIDO_CERTIFIED_L3plus"]`| The `"UPDATE_AVAILABLE"` status is not whitelisted by default |
  |`timeout`|`non_neg_integer()`|registration & authentication|`20 * 60`| The validity duration of a challenge, in seconds |
  |`android_key_allow_software_enforcement`|`boolean()`|registration|`false`| When registration is a Android key, determines whether software enforcement is acceptable (`true`) or only hardware enforcement is (`false`) |
  |`silent_authentication_enabled`|`boolean()`|authentication|`false`| See [https://github.com/fido-alliance/conformance-tools-issues/issues/434](https://github.com/fido-alliance/conformance-tools-issues/issues/434) |

  ## FIDO2 Metadata

  If you use attestation, you need to enabled metadata.

  ### Configuring MDSv3 metadata

  This is the official metadata service of the FIDO foundation.

  Set the `:update_metadata` environment variable to `true` and metadata will load
  automatically through HTTP from
  [https://mds3.fidoalliance.org/](https://fidoalliance.org/metadata/).

  ### Loading FIDO2 metadata from a directory

  In addition to the FIDO2 metadata service, it is possible to load metadata from a directory.
  To do so, the `:metadata_dir` application environment variable must be set to one of:
  - a `String.t()`: the path to the directory containing the metadata files
  - an `atom()`: in this case, the files are loaded from the `"fido2_metadata"` directory of the
  private (`"priv/"`) directory of the application (whose name is the atom)

  In both case, Wax tries to load all files (even directories and other special files).

  #### Example configuration

  ```elixir
  config :wax_,
    origin: "http://localhost:4000",
    rp_id: :auto,
    metadata_dir: :my_application
  ```

  will try to load all files of the `"priv/fido2_metadata/"` of the `:my_application` as FIDO2
  metadata statements. On failure, a warning is emitted.

  ## Security considerations

  - Make sure to understand the implications of not using attested credentials before
  accepting `none` or `self` attestation types, or disabling it for `packed` and `u2f`
  formats by disabling it with the `verify_trust_root` option
  - This library has **not** be reviewed by independent security / FIDO2 specialists - use
  it at your own risks or blindly trust its author! If you're knowledgeable about
  FIDO2 and willing to help reviewing it, please contact the author
  """

  alias Wax.Utils

  @type opts :: [opt()]

  @type opt ::
          {:attestation, String.t()}
          | {:origin, String.t()}
          | {:rp_id, String.t() | :auto}
          | {:user_verification, String.t()}
          | {:allow_credentials, [{Wax.AuthenticatorData.credential_id(), Wax.CoseKey.t()}]}
          | {:trusted_attestation_types, [Wax.Attestation.type()]}
          | {:verify_trust_root, boolean()}
          | {:acceptable_authenticator_statuses, [String.t()]}
          | {:issued_at, integer()}
          | {:timeout, non_neg_integer()}
          | {:android_key_allow_software_enforcement, boolean()}
          | {:silent_authentication_enabled, boolean()}

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
  def new_registration_challenge(opts \\ []) do
    opts
    |> Keyword.put(:type, :attestation)
    |> Wax.Challenge.new()
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
      if "tee" in metadata_statement["keyProtection"] or
         "secure_element" in metadata_statement["keyProtection"]
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

  Note that a user can have several `{credential id, cose key}` pairs, for example if the
  user uses different authenticators. The unique key (for storage, etc.) is therefore the tuple
  `{user id, credential id}`.

  In the success case, and after calling `register/3`, a server shall:
  1. Verify that no other user has the same credential id (and should fail otherwise)
  2. Store the new tuple `{credential id, cose key}` for the user
  """

  @spec register(binary(), Wax.ClientData.raw_string(), Wax.Challenge.t()) ::
          {:ok, {Wax.AuthenticatorData.t(), Wax.Attestation.result()}} | {:error, Exception.t()}
  def register(attestation_object_cbor, client_data_json_raw, challenge) do
    with :ok <- not_expired?(challenge),
         {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_create?(client_data),
         :ok <- valid_challenge?(client_data, challenge),
         :ok <- valid_origin?(client_data, challenge),
         client_data_hash = :crypto.hash(:sha256, client_data_json_raw),
         {:ok, att_data, _} <- Utils.CBOR.decode(attestation_object_cbor),
         %{"fmt" => att_fmt, "authData" => auth_data_bin, "attStmt" => att_stmt} = att_data,
         {:ok, auth_data} <- Wax.AuthenticatorData.decode(auth_data_bin),
         :ok <- valid_rp_id?(auth_data, challenge),
         :ok <- user_present_flag_set?(auth_data, challenge),
         :ok <- maybe_user_verified_flag_set?(auth_data, challenge),
         {:ok, attestation_result_data} <-
           Wax.Attestation.verify(att_stmt, att_fmt, auth_data, client_data_hash, challenge),
         :ok <- attestation_trustworthy?(attestation_result_data, challenge) do
      {:ok, {auth_data, attestation_result_data}}
    end
  end

  @doc """
  Generates a new challenge for authentication

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
  iex> Wax.new_authentication_challenge(allow_credentials: cred_ids_and_associated_keys)
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

  When self-discoverable credentials (so-called *resident keys*) are to be used,
  omit the `:allow_credentials` parameter and use instead  the `:credentials` parameter
  of `authenticate/6` when verifying.
  """

  @spec new_authentication_challenge(opts()) :: Wax.Challenge.t()
  def new_authentication_challenge(opts \\ []) do
    opts
    |> Keyword.put(:type, :authentication)
    |> Wax.Challenge.new()
  end

  @doc """
  Verifies a authentication response from the client WebAuthn javascript call

  The input params are:
  - `credential_id`: the credential id returned by the WebAuthn javascript API. Must be of
  the same form as the one passed to `new_authentication_challenge/1` as it will be
  compared against the previously retrieved valid credential ids
  - `auth_data_bin`: the authenticator data returned by the WebAuthn javascript API. Must
  be the raw binary, not the base64 encoded form
  - `sig`: the signature returned by the WebAuthn javascript API. Must
  be the raw binary, not the base64 encoded form
  - `client_data_json_raw`: the JSON string (and **not** the decoded JSON) of the client data
  JSON as returned by the WebAuthn javascript API
  - `challenge`: the challenge that was generated beforehand, and whose bytes has been sent
  to the browser and used as an input by the WebAuthn javascript API
  - `credentials`: see **Self-discoverable credentials** below

  The call returns `{:ok, authenticator_data}` in case of success, or `{:error, e}` otherwise.

  The `auth_data.sign_count` is the number of signature performed by this authenticator for this
  credential id, and can be used to detect cloning of authenticator. See point 17 of the
  [7.2. Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-1/#verifying-assertion)
  for more details.

  When using attestation, it's a good practice to check that the authenticator is not revoked
  after authentication. To do so:
  1. save the aaguid after registration along with the credential ID
  2. check the authenticator is not revoked after authentication using the aaguid saved in
  step 1. and `Wax.Metadata.get_by_aaguid/2`

  ### Self-discoverable credentials (*resident keys*)

  It is possible to call the WebAuthn API without `:allow_credentials` when the FIDO2 device
  is capable of storing self-discoverable credentials. In this case, the device prompts the user
  for an account to use, and authenticates the user.

  The WebAuthn API then returns a `userHandle` parameter, which is the user id which was used
  during registration.

  In this flow, it is not possible to know the allowed credentials in advance. Instead, one
  need to use the *user handle* to retrieve the user keys after the WebAuthn API returns,
  and before calling this function, with the retrieved keys passed as the `:credentials`
  parameter.
  """
  @spec authenticate(
          Wax.CredentialId.t(),
          binary(),
          binary(),
          Wax.ClientData.raw_string(),
          Wax.Challenge.t(),
          [{Wax.AuthenticatorData.credential_id(), Wax.CoseKey.t()}]
        ) :: {:ok, Wax.AuthenticatorData.t()} | {:error, Exception.t()}
  def authenticate(
        credential_id,
        auth_data_bin,
        sig,
        client_data_json_raw,
        challenge,
        credentials \\ []
      ) do
    with :ok <- not_expired?(challenge),
         {:ok, cose_key} <- cose_key_from_credential_id(credential_id, challenge, credentials),
         {:ok, auth_data} <- Wax.AuthenticatorData.decode(auth_data_bin),
         {:ok, client_data} <- Wax.ClientData.parse_raw_json(client_data_json_raw),
         :ok <- type_get?(client_data),
         :ok <- valid_challenge?(client_data, challenge),
         :ok <- valid_origin?(client_data, challenge),
         :ok <- valid_rp_id?(auth_data, challenge),
         :ok <- user_present_flag_set?(auth_data, challenge),
         :ok <- maybe_user_verified_flag_set?(auth_data, challenge),
         client_data_hash = :crypto.hash(:sha256, client_data_json_raw),
         :ok <- Wax.CoseKey.verify(auth_data_bin <> client_data_hash, cose_key, sig) do
      {:ok, auth_data}
    end
  end

  defp not_expired?(challenge) do
    current_time = System.system_time(:second)

    if current_time - challenge.issued_at < challenge.timeout do
      :ok
    else
      {:error, %Wax.ExpiredChallengeError{}}
    end
  end

  defp type_create?(client_data) do
    if client_data.type == :create do
      :ok
    else
      {:error, %Wax.InvalidClientDataError{reason: :create_type_expected}}
    end
  end

  defp type_get?(client_data) do
    if client_data.type == :get do
      :ok
    else
      {:error, %Wax.InvalidClientDataError{reason: :get_type_expected}}
    end
  end

  defp valid_challenge?(client_data, challenge) do
    if client_data.challenge == challenge.bytes do
      :ok
    else
      {:error, %Wax.InvalidClientDataError{reason: :challenge_mismatch}}
    end
  end

  def valid_origin?(client_data, challenge) do
    if same_host_or_subdomain?(client_data, challenge) do
      :ok
    else
      {:error, %Wax.InvalidClientDataError{reason: :origin_mismatch}}
    end
  end

  defp same_host_or_subdomain?(_client, nil), do: false

  defp same_host_or_subdomain?(client, challenge) do
     client_uri = URI.parse(client.origin)
     challenge_uri = URI.parse(challenge.origin)

     cond do
       client.origin == challenge.origin ->
         true
       client_uri.scheme == challenge_uri.scheme and
       client_uri.port == challenge_uri.port and
       segments(client_uri.host) == 1 + segments(challenge.rp_id) and
       String.ends_with?(client_uri.host, "." <> challenge.rp_id) ->
         true
       true ->
         false
     end
  end

  defp segments(host) do
    # 1. Remove all non-alphanumeric characters except dots and dashes
    # 2. Trim leading and trailing whitespace
    # 3. Split on dots
    # 4. Filter out empty segments
    # 5. Count the remaining segments

    Regex.replace(~r/[^A-Za-z0-9.\-]/, host, "")
    |> String.trim()
    |> String.split(".")
    |> Enum.filter(&(&1 != ""))
    |> Enum.count()
  end

  defp valid_rp_id?(auth_data, challenge) do
    if auth_data.rp_id_hash == :crypto.hash(:sha256, challenge.rp_id) do
      :ok
    else
      {:error, %Wax.InvalidClientDataError{reason: :rp_id_mismatch}}
    end
  end

  defp user_present_flag_set?(
         _auth_data,
         %Wax.Challenge{type: :authentication, silent_authentication_enabled: true}
       ) do
    :ok
  end

  defp user_present_flag_set?(auth_data, _challenge) do
    if auth_data.flag_user_present == true do
      :ok
    else
      {:error, %Wax.InvalidClientDataError{reason: :flag_user_present_not_set}}
    end
  end

  defp maybe_user_verified_flag_set?(auth_data, challenge) do
    case challenge.user_verification do
      "required" ->
        if auth_data.flag_user_verified do
          :ok
        else
          {:error, %Wax.InvalidClientDataError{reason: :user_not_verified}}
        end

      _ ->
        :ok
    end
  end

  defp attestation_trustworthy?({type, _, _}, challenge) do
    if type in challenge.trusted_attestation_types do
      :ok
    else
      {:error, %Wax.UntrustedAttestationTypeError{type: type, challenge: challenge}}
    end
  end

  defp cose_key_from_credential_id(credential_id, challenge, credentials) do
    credential_list =
      if challenge.allow_credentials == [] do
        # There's no credentials in the challenge, resident key was used instead
        # so we use the list of credentials passed as a parameter to authenticate/6
        credentials
      else
        challenge.allow_credentials
      end

    case List.keyfind(credential_list, credential_id, 0) do
      {_, cose_key} ->
        {:ok, cose_key}

      _ ->
        {:error, %Wax.InvalidClientDataError{reason: :credential_id_mismatch}}
    end
  end
end
