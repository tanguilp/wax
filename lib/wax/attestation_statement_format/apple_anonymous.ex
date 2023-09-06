defmodule Wax.AttestationStatementFormat.AppleAnonymous do
  require Logger

  @moduledoc false

  @behaviour Wax.AttestationStatementFormat

  @apple_root_cert_der """
                       -----BEGIN CERTIFICATE-----
                       MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
                       HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
                       bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
                       NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
                       A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
                       AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
                       xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
                       pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
                       2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
                       MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
                       jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
                       1bWeT0vT
                       -----END CERTIFICATE-----
                       """
                       |> X509.Certificate.from_pem!()
                       |> X509.Certificate.to_der()

  @impl Wax.AttestationStatementFormat
  def verify(
        att_stmt,
        auth_data,
        client_data_hash,
        challenge
      ) do
    with :ok <- valid_cbor?(att_stmt),
         %{"x5c" => [att_cert_der | _]} = att_stmt,
         att_cert = X509.Certificate.from_der!(att_cert_der),
         :ok <- check_vertificate_validity(att_cert),
         :ok <- check_nonces_match(att_cert, auth_data, client_data_hash),
         :ok <- check_keys_match(auth_data, att_cert),
         :ok <- check_certificate_path(att_stmt, auth_data, challenge) do
      {:ok, {:anonca, att_stmt["x5c"], nil}}
    else
      {:error, :malformed} ->
        {:error,
         %Wax.AttestationVerificationError{type: :apple, reason: :malformed_certificate}}

      {:error, _} = error ->
        error
    end
  end

  defp valid_cbor?(%{"x5c" => _}), do: :ok

  defp valid_cbor?(_),
    do: {:error, %Wax.AttestationVerificationError{type: :apple, reason: :invalid_cbor}}

  defp check_vertificate_validity(cert) do
    if Wax.Utils.Certificate.version(cert) == :v3 and
         Wax.Utils.Certificate.basic_constraints_ext_ca_component(cert) == false do
      :ok
    else
      {:error, %Wax.AttestationVerificationError{type: :apple, reason: :invalid_cert}}
    end
  end

  defp check_nonces_match(cert, auth_data, client_data_hash) do
    expected_nonce = :crypto.hash(:sha256, auth_data.raw_bytes <> client_data_hash)

    # manually decoding ASN
    {:Extension, _oid, _, <<_::binary-size(6), nonce::binary>>} =
      X509.Certificate.extension(cert, {1, 2, 840, 113_635, 100, 8, 2})

    if nonce == expected_nonce,
      do: :ok,
      else: {:error, %Wax.AttestationVerificationError{type: :apple, reason: :nonce_mismatch}}
  end

  defp check_keys_match(auth_data, att_cert) do
    att_cert_erlang_public_key = X509.Certificate.public_key(att_cert)

    auth_data_erlang_public_key =
      Wax.CoseKey.to_erlang_public_key(auth_data.attested_credential_data.credential_public_key)

    if att_cert_erlang_public_key == auth_data_erlang_public_key do
      :ok
    else
      {:error, %Wax.AttestationVerificationError{type: :apple, reason: :public_key_mismatch}}
    end
  end

  defp check_certificate_path(att_stmt, auth_data, challenge) do
    certs_der = Enum.reverse(att_stmt["x5c"])

    case Wax.Metadata.get_by_aaguid(auth_data.attested_credential_data.aaguid, challenge) do
      {:ok, metadata_statement} ->
        root_certs =
          metadata_statement["attestationRootCertificates"] |> Enum.map(&Base.decode64!/1)

        if Wax.Utils.PKIX.path_valid?(root_certs, certs_der) do
          :ok
        else
          {:error,
           %Wax.AttestationVerificationError{type: :apple, reason: :path_validation_failed}}
        end

      {:error, %Wax.MetadataStatementNotFoundError{}} ->
        if Wax.Utils.PKIX.path_valid?(@apple_root_cert_der, certs_der) do
          :ok
        else
          {:error,
           %Wax.AttestationVerificationError{type: :apple, reason: :path_validation_failed}}
        end

      {:error, _} = error ->
        error
    end
  end
end
