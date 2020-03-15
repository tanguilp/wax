defmodule Wax.AttestationStatementFormat.AndroidSafetynet do
  require Logger

  @moduledoc false

  @behaviour Wax.AttestationStatementFormat

  # GSR2 root certificate
  @root_cert_der """
  -----BEGIN CERTIFICATE-----
  MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G
  A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp
  Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1
  MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG
  A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
  hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL
  v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8
  eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq
  tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd
  C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa
  zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB
  mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH
  V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n
  bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG
  3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs
  J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO
  291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS
  ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd
  AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
  TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
  -----END CERTIFICATE-----
  """
  |> X509.Certificate.from_pem!()
  |> X509.Certificate.to_der()

  @impl Wax.AttestationStatementFormat
  def verify(
    att_stmt,
    auth_data,
    client_data_hash,
    %Wax.Challenge{attestation: "direct"} = challenge
  ) do
    [header_b64, payload_b64, _sig] = String.split(att_stmt["response"], ".")

    payload =
      payload_b64
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    header =
      header_b64
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    with :ok <- valid_cbor?(att_stmt),
         :ok <- verify_signature(att_stmt["response"], auth_data, challenge),
         :ok <- valid_safetynet_response?(payload, att_stmt["ver"]),
         :ok <- nonce_valid?(auth_data, client_data_hash, payload),
         :ok <- valid_cert_hostname?(header)
    do
      leaf_cert =
        header["x5c"]
        |> List.first()
        |> Base.decode64!()

      {:ok, {:basic, leaf_cert, nil}}
    end
  rescue
    _ ->
      {:error, :attestation_safetynet_invalid_att_stmt}
  end

  def verify(_attstmt, _auth_data, _client_data_hash, _challenge) do
    {:error, :invalid_attestation_conveyance_preference}
  end

  @spec valid_cbor?(Wax.Attestation.statement()) :: :ok | {:error, any()}
  defp valid_cbor?(att_stmt) do
    if is_binary(att_stmt["ver"])
    and is_binary(att_stmt["response"])
    and length(Map.keys(att_stmt)) == 2 # only these two keys
    do
      :ok
    else
      {:error, :attestation_safetynet_invalid_cbor}
    end
  end

  @spec verify_signature(
    String.t(),
    Wax.AuthenticatorData.t(),
    Wax.Challenge.t()
  ) :: :ok | {:error, atom()}
  defp verify_signature(jws, auth_data, challenge) do
    case Wax.Metadata.get_by_aaguid(auth_data.attested_credential_data.aaguid, challenge) do
      %Wax.Metadata.Statement{} = attestation_statement ->
        [header_b64, _payload_b64, _sig_b64] = String.split(jws, ".")

        jws_alg =
          header_b64
          |> Base.url_decode64!(padding: false)
          |> Jason.decode!()
          |> Map.get("alg")

        if algs_match?(attestation_statement.authentication_algorithm, jws_alg) do
          do_verify_signature(jws, attestation_statement.attestation_root_certificates)
        else
          {:error, :attestation_safetynet_algs_dont_match}
        end

      _ ->
        do_verify_signature(jws, [@root_cert_der])
    end
  end

  @spec algs_match?(Wax.Metadata.Statement.authentication_algorithm(), String.t()) :: boolean()
  defp algs_match?(:alg_sign_secp256r1_ecdsa_sha256_raw, "ES256"), do: true
  defp algs_match?(:alg_sign_secp256r1_ecdsa_sha256_der, "ES256"), do: true
  defp algs_match?(:alg_sign_rsassa_pss_sha256_raw, "PS256"), do: true
  defp algs_match?(:alg_sign_rsassa_pss_sha256_der, "PS256"), do: true
  defp algs_match?(:alg_sign_secp256k1_ecdsa_sha256_raw, "ES256K"), do: true
  defp algs_match?(:alg_sign_secp256k1_ecdsa_sha256_der, "ES256K"), do: true
  defp algs_match?(:alg_sign_rsassa_pss_sha384_raw, "PS384"), do: true
  defp algs_match?(:alg_sign_rsassa_pss_sha512_raw, "PS512"), do: true
  defp algs_match?(:alg_sign_rsassa_pkcsv15_sha256_raw, "RS256"), do: true
  defp algs_match?(:alg_sign_rsassa_pkcsv15_sha384_raw, "RS384"), do: true
  defp algs_match?(:alg_sign_rsassa_pkcsv15_sha512_raw, "RS512"), do: true
  defp algs_match?(:alg_sign_rsassa_pkcsv15_sha1_raw, "RS1"), do: true
  defp algs_match?(:alg_sign_secp384r1_ecdsa_sha384_raw, "ES384"), do: true
  defp algs_match?(:alg_sign_secp521r1_ecdsa_sha512_raw, "ES512"), do: true
  defp algs_match?(:alg_sign_ed25519_eddsa_sha256_raw, "EdDSA"), do: true
  defp algs_match?(_, _), do: false

  @spec do_verify_signature(String.t(), [binary()]) :: :ok | {:error, atom()}
  defp do_verify_signature(_jws, []) do
    {:error, :attestation_safetynet_invalid_jws_signature}
  end

  defp do_verify_signature(jws, [root_cert_der | remaining_root_certs_der]) do
    case Wax.Utils.JWS.verify_with_x5c(jws, root_cert_der) do
      :ok ->
        :ok

      {:error, _} ->
        do_verify_signature(jws, remaining_root_certs_der)
    end
  end

  @spec valid_safetynet_response?(map() | Keyword.t() | nil, String.t()) :: :ok | {:error, any()}

  defp valid_safetynet_response?(%{} = safetynet_response, version) do
    Logger.debug("#{__MODULE__}: verifying SafetyNet response validity: " <>
      "#{inspect(safetynet_response)}")

    (
      safetynet_response["ctsProfileMatch"] == true
      and version != nil
      and is_integer(safetynet_response["timestampMs"])
      and safetynet_response["timestampMs"] < :os.system_time(:millisecond)
      and safetynet_response["timestampMs"] > :os.system_time(:millisecond) - 60 * 1000
    )
    |> if do
      case Integer.parse(version) do
        {version_int, _} when version_int > 0 ->
          :ok

        _ ->
          {:error, :attestation_safetynet_invalid_version}
      end
    else
      {:error, :attestation_safetynet_invalid_ctsProfileMatch}
    end
  end

  defp valid_safetynet_response?(_, _), do: {:error, :attestation_safetynet_invalid_payload}

  @spec nonce_valid?(Wax.AuthenticatorData.t(), binary(), map())
    :: :ok | {:error, any()}

  defp nonce_valid?(auth_data, client_data_hash, payload) do
    expected_nonce =
      Base.encode64(:crypto.hash(:sha256, auth_data.raw_bytes <> client_data_hash))

    if payload["nonce"] == expected_nonce do
      :ok
    else
      {:error, :attestation_safetynet_invalid_nonce}
    end
  end

  @spec valid_cert_hostname?(map()) :: :ok | {:error, any()}
  defp valid_cert_hostname?(header) do
    leaf_cert =
      header["x5c"]
      |> List.first()
      |> Base.decode64!()
      |> X509.Certificate.from_der!()

    Logger.debug("#{__MODULE__}: verifying certificate: #{inspect(leaf_cert)}")

    # {2, 5, 4, 3} is the OID for CN
    case X509.Certificate.subject(leaf_cert, {2, 5, 4, 3}) do
      ["attest.android.com"] ->
        :ok

      _ ->
        {:error, :attestation_safetynet_invalid_hostname}
    end
  end
end
