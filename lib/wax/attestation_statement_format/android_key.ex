defmodule Wax.AttestationStatementFormat.AndroidKey do
  #FIXME: test cert can be found at https://fidoalliance.org/wp-content/uploads/Hardware-backed_Keystore_White_Paper_June2018.pdf
  require Logger

  @moduledoc false

  @asn_output_dir 'android_key/asn_generated'

  # from https://github.com/NuclearAndroidProject1/android_hardware_libhardware/blob/master/include/hardware/keymaster_defs.h
  @km_origin_generated 0
  @km_purpose_sign 2

  @behaviour Wax.AttestationStatementFormat

  @impl Wax.AttestationStatementFormat
  def verify(att_stmt, auth_data, client_data_hash, _verify_trust_root) do
    #FIXME: shall we verify the cert chain?
    with :ok <- valid_cbor?(att_stmt),
         {:ok, leaf_cert} <- X509.Certificate.from_der(List.first(att_stmt["x5c"])),
         :ok <- valid_signature?(att_stmt["sig"], auth_data.raw_bytes <> client_data_hash, leaf_cert),
         :ok <- public_key_matches_first_cert?(auth_data, leaf_cert),
         :ok <- valid_extension_data?(leaf_cert, client_data_hash)
    do
      {:ok, {:basic, att_stmt["x5c"], nil}}
    else
      error ->
        error
    end
  end

  @spec valid_cbor?(Wax.Attestation.statement()) :: :ok | {:error, any()}
  defp valid_cbor?(att_stmt) do
    if is_binary(att_stmt["sig"])
    and is_list(att_stmt["x5c"])
    and length(Map.keys(att_stmt)) == 2 # only these two keys
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

  @spec valid_extension_data?(X509.Certificate.t(), binary()) :: :ok | {:error, any()}
  defp valid_extension_data?(cert, client_data_hash) do
    try do
      {:Extension, _oid, _critical, asn} =
        X509.Certificate.extension(cert, {1, 3, 6, 1, 4, 1, 11129, 2, 1, 17})

        if asn_v3_valid?(asn, client_data_hash) or asn_v2_valid?(asn, client_data_hash)
          or asn_v1_valid?(asn, client_data_hash) do
          :ok
        else
          {:error, :attestation_androidkey_invalid_asn_attestation}
        end
    rescue
      _ ->
        {:error, :attestation_androidkey_malformed_asn1_record}
    end
  end

  @spec asn_v1_valid?(binary(), binary) :: boolean
  defp asn_v1_valid?(asn, client_data_hash) do
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
        #FIXME: see https://github.com/w3c/webauthn/issues/1022
        (
          origin_software_enforced == @km_origin_generated and
          purpose_software_enforced == @km_purpose_sign
        )
        or
        (
          origin_tee_enforced == @km_origin_generated and
          purpose_tee_enforced == @km_purpose_sign
        )

      _ ->
        false
    end
  end

  @spec asn_v2_valid?(binary(), binary) :: boolean
  defp asn_v2_valid?(asn, client_data_hash) do
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
        #FIXME: see https://github.com/w3c/webauthn/issues/1022
        (
          origin_software_enforced == @km_origin_generated and
          purpose_software_enforced == @km_purpose_sign
        )
        or
        (
          origin_tee_enforced == @km_origin_generated and
          purpose_tee_enforced == @km_purpose_sign
        )

      _ ->
        false
    end
  end

  @spec asn_v3_valid?(binary(), binary) :: boolean
  defp asn_v3_valid?(asn, client_data_hash) do
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
            _attestationIdModel_te,
            _vendorPatchLevel_te,
            _bootPatchLevel_te
          }}} ->
        #FIXME: see https://github.com/w3c/webauthn/issues/1022
        (
          origin_software_enforced == @km_origin_generated and
          purpose_software_enforced == @km_purpose_sign
        )
        or
        (
          origin_tee_enforced == @km_origin_generated and
          purpose_tee_enforced == @km_purpose_sign
        )

      _ ->
        false
    end
  end

  @doc """
  Parse the ASN files and create the ASN modules

  See ASN schema at https://developer.android.com/training/articles/security-key-attestation#certificate_schema
  """

  @spec install_asn1_module() :: :ok

  def install_asn1_module() do
    File.mkdir(:code.priv_dir(:wax) ++ '/' ++ @asn_output_dir)
    #FIXME: does it work once used in an erlang release?

    :asn1ct.compile(
      :code.priv_dir(:wax) ++ '/android_key/AndroidKeyAttestationV1.asn1',
      [{:outdir, :code.priv_dir(:wax) ++ '/' ++ @asn_output_dir}]
    )

    :asn1ct.compile(
      :code.priv_dir(:wax) ++ '/android_key/AndroidKeyAttestationV2.asn1',
      [{:outdir, :code.priv_dir(:wax) ++ '/' ++ @asn_output_dir}]
    )

    :asn1ct.compile(
      :code.priv_dir(:wax) ++ '/android_key/AndroidKeyAttestationV3.asn1',
      [{:outdir, :code.priv_dir(:wax) ++ '/' ++ @asn_output_dir}]
    )
  end
end
