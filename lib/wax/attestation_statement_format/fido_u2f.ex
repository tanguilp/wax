defmodule Wax.AttestationStatementFormat.FIDOU2F do
  @moduledoc false

  @behaviour Wax.AttestationStatementFormat

  @impl Wax.AttestationStatementFormat
  def verify(
        att_stmt,
        auth_data,
        client_data_hash,
        %Wax.Challenge{attestation: "direct"} = challenge
      ) do
    with :ok <- valid_cbor?(att_stmt),
         {:ok, pub_key} <- extract_and_verify_public_key(att_stmt),
         :ok <- verify_aaguid_null(auth_data),
         public_key_u2f <- get_raw_cose_key(auth_data),
         verification_data <- get_verification_data(auth_data, client_data_hash, public_key_u2f),
         :ok <- valid_signature?(att_stmt["sig"], verification_data, pub_key),
         {:ok, maybe_metadata_statement} <-
           attestation_certificate_valid?(att_stmt["x5c"], challenge) do
      attestation_type = determine_attestation_type(maybe_metadata_statement)

      {:ok, {attestation_type, att_stmt["x5c"], maybe_metadata_statement}}
    end
  end

  def verify(_attstmt, _auth_data, _client_data_hash, _challenge) do
    {:error, :invalid_attestation_conveyance_preference}
  end

  defp valid_cbor?(att_stmt) do
    # only these two keys
    if is_binary(att_stmt["sig"]) and
         is_list(att_stmt["x5c"]) and
         length(Map.keys(att_stmt)) == 2 do
      :ok
    else
      {:error, :attestation_fidou2f_invalid_cbor}
    end
  end

  defp extract_and_verify_public_key(att_stmt) do
    case att_stmt["x5c"] do
      [der] ->
        cert = X509.Certificate.from_der!(der)

        pub_key = X509.Certificate.public_key(cert)

        if Wax.Utils.Certificate.public_key_algorithm(cert) == {1, 2, 840, 10045, 2, 1} and
             elem(pub_key, 1) == {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}} do
          {:ok, pub_key}
        else
          {:error, :attestation_fidou2f_invalid_public_key_algorithm}
        end

      _ ->
        {:error, :attestation_fidou2f_multiple_x5c}
    end
  end

  defp verify_aaguid_null(auth_data) do
    if :binary.decode_unsigned(auth_data.attested_credential_data.aaguid) == 0 do
      :ok
    else
      {:error, :attestation_fidou2f_non_nil_aaguid}
    end
  end

  defp get_raw_cose_key(auth_data) do
    x = auth_data.attested_credential_data.credential_public_key[-2]
    y = auth_data.attested_credential_data.credential_public_key[-3]

    <<04>> <> x <> y
  end

  defp get_verification_data(auth_data, client_data_hash, public_key_u2f) do
    <<0>> <>
      auth_data.rp_id_hash <>
      client_data_hash <>
      auth_data.attested_credential_data.credential_id <>
      public_key_u2f
  end

  defp valid_signature?(sig, verification_data, pub_key) do
    if :public_key.verify(verification_data, :sha256, sig, pub_key) do
      :ok
    else
      {:error, :attestation_fidou2f_invalid_signature}
    end
  end

  defp attestation_certificate_valid?(
         [leaf_cert | _],
         %Wax.Challenge{verify_trust_root: true} = challenge
       ) do
    acki = Wax.Utils.Certificate.attestation_certificate_key_identifier(leaf_cert)

    Wax.Metadata.get_by_acki(acki, challenge)
  end

  defp attestation_certificate_valid?(_, %Wax.Challenge{verify_trust_root: false}) do
    {:ok, nil}
  end

  defp determine_attestation_type(nil) do
    :uncertain
  end

  defp determine_attestation_type(metadata_statement) do
    attestation_types = metadata_statement["metadataStatement"]["attestationTypes"]

    cond do
      "basic_full" in attestation_types ->
        :basic

      "attca" in attestation_types ->
        :attca

      true ->
        :uncertain
    end
  end
end
