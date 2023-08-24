defmodule Wax.AttestationStatementFormat.AndroidSafetynet do
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
         :ok <- valid_cert_hostname?(header) do
      trust_path =
        header["x5c"]
        |> Enum.map(&Base.decode64!/1)

      {:ok, {:basic, trust_path, nil}}
    end
  rescue
    _ ->
      {:error, %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_att_stmt}}
  end

  def verify(_attstmt, _auth_data, _client_data_hash, _challenge) do
    {:error,
     %Wax.AttestationVerificationError{
       type: :safetynet,
       reason: :invalid_attestation_conveyance_preference
     }}
  end

  defp valid_cbor?(att_stmt) do
    # only these two keys
    if is_binary(att_stmt["ver"]) and
         is_binary(att_stmt["response"]) and
         length(Map.keys(att_stmt)) == 2 do
      :ok
    else
      {:error, %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_cbor}}
    end
  end

  defp verify_signature(jws, auth_data, challenge) do
    case Wax.Metadata.get_by_aaguid(auth_data.attested_credential_data.aaguid, challenge) do
      {:ok, metadata_statement} ->
        authentication_algorithms = metadata_statement["authenticationAlgorithms"]

        [header_b64, _payload_b64, _sig_b64] = String.split(jws, ".")

        jws_alg =
          header_b64
          |> Base.url_decode64!(padding: false)
          |> Jason.decode!()
          |> Map.get("alg")

        root_certificates =
          Enum.map(metadata_statement["attestationRootCertificates"], &Base.decode64!/1)

        do_verify_signature(jws, root_certificates)

      {:error, %Wax.MetadataStatementNotFoundError{}} ->
        do_verify_signature(jws, [@root_cert_der])

      {:error, _} = error ->
        error
    end
  end

  defp do_verify_signature(_jws, []) do
    {:error, %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_jws_signature}}
  end

  defp do_verify_signature(jws, [root_cert_der | remaining_root_certs_der]) do
    case Wax.Utils.JWS.verify_with_x5c(jws, root_cert_der) do
      {:ok, _} ->
        :ok

      {:error, _} ->
        do_verify_signature(jws, remaining_root_certs_der)
    end
  end

  defp valid_safetynet_response?(%{} = safetynet_response, version) do
    (safetynet_response["ctsProfileMatch"] == true and
       version != nil and
       is_integer(safetynet_response["timestampMs"]) and
       safetynet_response["timestampMs"] < :os.system_time(:millisecond) and
       safetynet_response["timestampMs"] > :os.system_time(:millisecond) - 60 * 1000)
    |> if do
      case Integer.parse(version) do
        {version_int, _} when version_int > 0 ->
          :ok

        _ ->
          {:error, %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_version}}
      end
    else
      {:error,
       %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_ctsProfileMatch}}
    end
  end

  defp valid_safetynet_response?(_, _),
    do: {:error, %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_payload}}

  defp nonce_valid?(auth_data, client_data_hash, payload) do
    expected_nonce = Base.encode64(:crypto.hash(:sha256, auth_data.raw_bytes <> client_data_hash))

    if payload["nonce"] == expected_nonce do
      :ok
    else
      {:error, %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_nonce}}
    end
  end

  defp valid_cert_hostname?(header) do
    leaf_cert =
      header["x5c"]
      |> List.first()
      |> Base.decode64!()
      |> X509.Certificate.from_der!()

    # {2, 5, 4, 3} is the OID for CN
    case X509.Certificate.subject(leaf_cert, {2, 5, 4, 3}) do
      ["attest.android.com"] ->
        :ok

      _ ->
        {:error, %Wax.AttestationVerificationError{type: :safetynet, reason: :invalid_hostname}}
    end
  end
end
