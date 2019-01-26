defmodule Wax.AttestationStatementFormat.FIDOU2F do
  require Logger

  @behaviour Wax.AttestationStatementFormat

  @impl Wax.AttestationStatementFormat
  def verify(att_stmt, auth_data, client_data_hash, _auth_data_bin) do
    with :ok <- valid_cbor?(att_stmt),
         {:ok, ec_pk} <- extract_and_verify_certificate(att_stmt),
         public_key_u2f <- get_raw_cose_key(auth_data),
         verification_data <- get_verification_data(auth_data, client_data_hash, public_key_u2f),
         :ok <- valid_signature?(att_stmt["sig"], verification_data, ec_pk)
    do
      {:ok, {:basic, att_stmt["x5c"]}}
    else
      error ->
        error
    end
  end

  @spec valid_cbor?(Wax.Attestation.Statement.t()) :: :ok | {:error, any()}
  defp valid_cbor?(att_stmt) do
    if is_binary(att_stmt["sig"])
    and is_list(att_stmt["x5c"])
    and length(Map.keys(att_stmt)) == 2 # only these two keys
    do
      :ok
    else
      {:error, :invalid_attestation_statement_cbor}
    end
  end

  @spec extract_and_verify_certificate(Wax.Attestation.Statement.t()) ::
  {:ok, any()} | {:error, any()} #FIXME any()
  defp extract_and_verify_certificate(att_stmt) do
    case att_stmt["x5c"] do
      [der] ->
        case :public_key.pkix_decode_cert(der, :otp) do
          #FIXME: does pkix_decode_cert/2 checks the cert?
          # The WebAuthn spec does not say the cert should be checked though
          {:OTPCertificate,
            {:OTPTBSCertificate, :v3, _,
              _,
              _,
              _,
              _,
              {:OTPSubjectPublicKeyInfo,
                {:PublicKeyAlgorithm, {1, 2, 840, 10045, 2, 1}, # Elliptic curve
                  {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},  # secp256r1
                ec_pk}, _, _,
              #{:ECPoint, ecdsa_public}}, _, _,
              _}, _,
            _} ->
              {:ok, ec_pk}

            _ ->
              {:error, :fido_u2f_attestation_invalid_public_key_algorithm}
        end

        _ ->
          {:error, :fido_u2f_attestation_multiple_x5c}
    end
  end

  @spec get_raw_cose_key(Wax.AuthData.t()) :: binary()
  def get_raw_cose_key(auth_data) do
    x = auth_data.attested_credential_data.credential_public_key[-2]
    y = auth_data.attested_credential_data.credential_public_key[-3]

    <<04>> <> x <> y
  end

  @spec get_verification_data(Wax.AuthData.t(), Wax.ClientData.hash(), binary()) :: binary()
  def get_verification_data(auth_data, client_data_hash, public_key_u2f) do
    <<0>>
    <> auth_data.rp_id_hash
    <> client_data_hash
    <> auth_data.attested_credential_data.credential_id
    <> public_key_u2f
  end

  @spec valid_signature?(binary(), binary(), {:ECPoint, binary()}) :: :ok | {:error, any()}
  def valid_signature?(sig, verification_data, ec_pk) do
    #FIXME: use X509 module instead
    if :public_key.verify(verification_data, :sha256, sig, {ec_pk, {:namedCurve, :secp256r1}}) do
      :ok
    else
      {:error, :fido_u2f_invalid_attestation_signature}
    end
  end
end
