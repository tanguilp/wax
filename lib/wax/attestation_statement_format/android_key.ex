defmodule Wax.AttestationStatementFormat.AndroidKey do
  # test cert can be found at https://fidoalliance.org/wp-content/uploads/Hardware-backed_Keystore_White_Paper_June2018.pdf
  require Logger

  @moduledoc false

  # from https://github.com/NuclearAndroidProject1/android_hardware_libhardware/blob/master/include/hardware/keymaster_defs.h
  @km_origin_generated 0
  @km_purpose_sign 2

  @android_key_root_cert_der """
  -----BEGIN CERTIFICATE-----
  MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
  EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
  dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
  VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
  HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
  EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
  BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
  QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
  KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
  dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
  BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
  EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
  SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
  C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
  -----END CERTIFICATE-----
  """
  |> X509.Certificate.from_pem!()
  |> X509.Certificate.to_der()

  @behaviour Wax.AttestationStatementFormat

  @impl Wax.AttestationStatementFormat
  def verify(
    att_stmt,
    auth_data,
    client_data_hash,
    %Wax.Challenge{attestation: "direct"} = challenge
  ) do
    #see: https://medium.com/@tangui.lepense/hi-the-webauthn-specification-https-www-w3-org-tr-webauthn-android-key-attestation-6e5e5daaa03f
    with :ok <- valid_cbor?(att_stmt),
         cert_chain = att_stmt["x5c"],
         {:ok, leaf_cert} <- X509.Certificate.from_der(List.first(cert_chain)),
         :ok <- valid_signature?(att_stmt["sig"], auth_data.raw_bytes <> client_data_hash, leaf_cert),
         :ok <- public_key_matches_first_cert?(auth_data, leaf_cert),
         :ok <- valid_extension_data?(leaf_cert, client_data_hash, challenge),
         :ok <- validate_x5c_path(auth_data, cert_chain, challenge)
    do
      {:ok, {:basic, att_stmt["x5c"], nil}}
    else
      {:error, {:bad_cert, _}} ->
        {:error, :attestation_androidkey_path_validation_bad_cert}

      error ->
        error
    end
  end

  def verify(_attstmt, _auth_data, _client_data_hash, _challenge) do
    {:error, :invalid_attestation_conveyance_preference}
  end

  @spec valid_cbor?(Wax.Attestation.statement()) :: :ok | {:error, any()}
  defp valid_cbor?(att_stmt) do
    if is_binary(att_stmt["sig"])
    and is_list(att_stmt["x5c"])
    and is_integer(att_stmt["alg"])
    and length(Map.keys(att_stmt)) == 3
    do
      :ok
    else
      {:error, :attestation_androidkey_invalid_cbor}
    end
  end

  @spec valid_signature?(binary(), binary(), X509.Certificate.t()) :: :ok | {:error, any()}
  defp valid_signature?(sig, verification_data, first_cert) do
    public_key = X509.Certificate.public_key(first_cert)

    if :public_key.verify(verification_data, :sha256, sig, public_key) do
      :ok
    else
      {:error, :attestation_androidkey_invalid_signature}
    end
  end

  @spec public_key_matches_first_cert?(Wax.AuthenticatorData.t(), X509.Certificate.t())
  :: :ok | {:error, any()}

  defp public_key_matches_first_cert?(auth_data, first_cert) do
    pk = auth_data.attested_credential_data.credential_public_key

    if Wax.CoseKey.to_erlang_public_key(pk) == X509.Certificate.public_key(first_cert) do
        :ok
    else
      {:error, :attestation_androidkey_keys_mismatch}
    end
  end

  @spec valid_extension_data?(X509.Certificate.t(), binary(), Wax.Challenge.t()) ::
  :ok
  | {:error, any()}
  defp valid_extension_data?(cert, client_data_hash, challenge) do
    try do
      {:Extension, _oid, _critical, asn} =
        X509.Certificate.extension(cert, {1, 3, 6, 1, 4, 1, 11129, 2, 1, 17})

        if asn_v3_valid?(asn, client_data_hash, challenge)
          or asn_v2_valid?(asn, client_data_hash, challenge)
          or asn_v1_valid?(asn, client_data_hash, challenge)
        do
          :ok
        else
          {:error, :attestation_androidkey_invalid_asn_attestation}
        end
    rescue
      _ ->
        {:error, :attestation_androidkey_malformed_asn1_record}
    end
  end

  @spec asn_v1_valid?(binary(), binary, Wax.Challenge.t()) :: boolean
  defp asn_v1_valid?(asn, client_data_hash, challenge) do
    case :AndroidKeyAttestationV1.decode(:AndroidKeyAttestationV1, asn) do
      {:ok,
        {:AndroidKeyAttestationV1, 1, _, _, _,
          ^client_data_hash, _,
          {:AuthorizationList,
            purpose_software_enforced,
            _algorithm,
            _keySize,
            _digest,
            _padding,
            _ecCurve,
            _rsaPublicExponent,
            _activeDateTime,
            _originationExpireDateTime,
            _usageExpireDateTime,
            _noAuthRequired,
            _userAuthType,
            _authTimeout,
            _allowWhileOnBody,
            :asn1_NOVALUE, # allApplications
            _applicationId,
            _creationDateTime,
            origin_software_enforced,
            _rollbackResistant,
            _rootOfTrust,
            _osVersion,
            _osPatchLevel
          },
          {:AuthorizationList,
            purpose_tee_enforced,
            _algorithm_te,
            _keySize_te,
            _digest_te,
            _padding_te,
            _ecCurve_te,
            _rsaPublicExponent_te,
            _activeDateTime_te,
            _originationExpireDateTime_te,
            _usageExpireDateTime_te,
            _noAuthRequired_te,
            _userAuthType_te,
            _authTimeout_te,
            _allowWhileOnBody_te,
            :asn1_NOVALUE, # allApplications
            _applicationId_te,
            _creationDateTime_te,
            origin_tee_enforced,
            _rollbackResistant_te,
            _rootOfTrust_te,
            _osVersion_te,
            _osPatchLevel_te
          }}} ->
        (
          challenge.android_key_allow_software_enforcement == true and
          @km_origin_generated == origin_software_enforced and
          @km_purpose_sign in purpose_software_enforced
        )
        or
        (
          @km_origin_generated == origin_tee_enforced and
          @km_purpose_sign in purpose_tee_enforced
        )

      _ ->
        false
    end
  end

  @spec asn_v2_valid?(binary(), binary, Wax.Challenge.t()) :: boolean
  defp asn_v2_valid?(asn, client_data_hash, challenge) do
    case :AndroidKeyAttestationV2.decode(:AndroidKeyAttestationV2, asn) do
      {:ok,
        {:AndroidKeyAttestationV2, 2, _, _, _,
          ^client_data_hash, _,
          {:AuthorizationList,
            purpose_software_enforced,
            _algorithm,
            _keySize,
            _digest,
            _padding,
            _ecCurve,
            _rsaPublicExponent,
            _activeDateTime,
            _originationExpireDateTime,
            _usageExpireDateTime,
            _noAuthRequired,
            _userAuthType,
            _authTimeout,
            _allowWhileOnBody,
            :asn1_NOVALUE, # allApplications
            _applicationId,
            _creationDateTime,
            origin_software_enforced,
            _rollbackResistant,
            _rootOfTrust,
            _osVersion,
            _osPatchLevel,
            _attestationApplicationId,
            _attestationIdBrand,
            _attestationIdDevice,
            _attestationIdProduct,
            _attestationIdSerial,
            _attestationIdImei,
            _attestationIdMeid,
            _attestationIdManufacturer,
            _attestationIdModel
          },
          {:AuthorizationList,
            purpose_tee_enforced,
            _algorithm_te,
            _keySize_te,
            _digest_te,
            _padding_te,
            _ecCurve_te,
            _rsaPublicExponent_te,
            _activeDateTime_te,
            _originationExpireDateTime_te,
            _usageExpireDateTime_te,
            _noAuthRequired_te,
            _userAuthType_te,
            _authTimeout_te,
            _allowWhileOnBody_te,
            :asn1_NOVALUE, # allApplications
            _applicationId_te,
            _creationDateTime_te,
            origin_tee_enforced,
            _rollbackResistant_te,
            _rootOfTrust_te,
            _osVersion_te,
            _osPatchLevel_te,
            _attestationApplicationId_te,
            _attestationIdBrand_te,
            _attestationIdDevice_te,
            _attestationIdProduct_te,
            _attestationIdSerial_te,
            _attestationIdImei_te,
            _attestationIdMeid_te,
            _attestationIdManufacturer_te,
            _attestationIdModel_te
          }}} ->
        (
          challenge.android_key_allow_software_enforcement == true and
          @km_origin_generated == origin_software_enforced and
          @km_purpose_sign in purpose_software_enforced
        )
        or
        (
          @km_origin_generated == origin_tee_enforced and
          @km_purpose_sign in purpose_tee_enforced
        )

      _ ->
        false
    end
  end

  @spec asn_v3_valid?(binary(), binary, Wax.Challenge.t()) :: boolean
  defp asn_v3_valid?(asn, client_data_hash, challenge) do
    case :AndroidKeyAttestationV3.decode(:AndroidKeyAttestationV3, asn) do
      {:ok,
        {:AndroidKeyAttestationV3, 3, _, _, _,
          ^client_data_hash, _,
          {:AuthorizationList,
            purpose_software_enforced,
            _algorithm,
            _keySize,
            _digest,
            _padding,
            _ecCurve,
            _rsaPublicExponent,
            _rollback_persistence,
            _activeDateTime,
            _originationExpireDateTime,
            _usageExpireDateTime,
            _noAuthRequired,
            _userAuthType,
            _authTimeout,
            _allowWhileOnBody,
            _trustedUserPresenceRequired,
            _trustedConfirmationRequired,
            _unlockedDeviceRequired,
            :asn1_NOVALUE, # allApplications
            _applicationId,
            _creationDateTime,
            origin_software_enforced,
            _rootOfTrust,
            _osVersion,
            _osPatchLevel,
            _attestationApplicationId,
            _attestationIdBrand,
            _attestationIdDevice,
            _attestationIdProduct,
            _attestationIdSerial,
            _attestationIdImei,
            _attestationIdMeid,
            _attestationIdManufacturer,
            _attestationIdModel,
            _vendorPatchLevel,
            _bootPatchLevel
          },
          {:AuthorizationList,
            purpose_tee_enforced,
            _algorithm_te,
            _keySize_te,
            _digest_te,
            _padding_te,
            _ecCurve_te,
            _rsaPublicExponent_te,
            _rollback_persistence_te,
            _activeDateTime_te,
            _originationExpireDateTime_te,
            _usageExpireDateTime_te,
            _noAuthRequired_te,
            _userAuthType_te,
            _authTimeout_te,
            _allowWhileOnBody_te,
            _trustedUserPresenceRequired_te,
            _trustedConfirmationRequired_te,
            _unlockedDeviceRequired_te,
            :asn1_NOVALUE, # allApplications
            _applicationId_te,
            _creationDateTime_te,
            origin_tee_enforced,
            _rootOfTrust_te,
            _osVersion_te,
            _osPatchLevel_te,
            _attestationApplicationId_te,
            _attestationIdBrand_te,
            _attestationIdDevice_te,
            _attestationIdProduct_te,
            _attestationIdSerial_te,
            _attestationIdImei_te,
            _attestationIdMeid_te,
            _attestationIdManufacturer_te,
            _attestationIdModel_te,
            _vendorPatchLevel_te,
            _bootPatchLevel_te
          }}} ->
        (
          challenge.android_key_allow_software_enforcement == true and
          @km_origin_generated == origin_software_enforced and
          @km_purpose_sign in purpose_software_enforced
        )
        or
        (
          @km_origin_generated == origin_tee_enforced and
          @km_purpose_sign in purpose_tee_enforced
        )

      _ ->
        false
    end
  end

  @spec validate_x5c_path(
    Wax.AuthenticatorData.t(),
    [binary()],
    Wax.Challenge.t()
  ) :: :ok | {:error, atom()}
  defp validate_x5c_path(auth_data, cert_chain, challenge) do
    root_certs =
      case Wax.Metadata.get_by_aaguid(auth_data.attested_credential_data.aaguid, challenge) do
        %Wax.Metadata.Statement{} = attestation_statement ->
          attestation_statement.attestation_root_certificates

        _ ->
          [@android_key_root_cert_der]
      end

    do_validate_x5c_path(root_certs, cert_chain)
  end

  @spec do_validate_x5c_path(
    root_certs :: [binary()],
    cert_chain :: [binary()]
  ) :: :ok | {:error, atom()}
  defp do_validate_x5c_path([], _) do
    {:error, :attestation_androidkey_path_validation_failed}
  end

  defp do_validate_x5c_path([root_cert_der | remaining_root_certs], cert_chain) do
    case :public_key.pkix_path_validation(root_cert_der, Enum.reverse(cert_chain), []) do
      {:ok, _} ->
        :ok

      {:error, _} ->
        do_validate_x5c_path(remaining_root_certs, cert_chain)
    end
  end
end
