defmodule Wax.AttestationStatementFormat.TPM do
  require Logger

  @moduledoc false

  #structures described in http://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf

  @behaviour Wax.AttestationStatementFormat

  #@tpm_alg_error  0x0000
  @tpm_alg_rsa  0x0001
  #@tpm_alg_sha  0x0004
  @tpm_alg_sha1 0x0004
  #@tpm_alg_hmac 0x0005
  #@tpm_alg_aes  0x0006
  #@tpm_alg_mgf1 0x0007
  #@tpm_alg_keyedhash 0x0008
  #@tpm_alg_xor  0x000a
  @tpm_alg_sha256 0x000b
  @tpm_alg_sha384 0x000c
  @tpm_alg_sha512 0x000d
  @tpm_alg_null 0x0010
  #@tpm_alg_sm3_256  0x0012
  #@tpm_alg_sm4  0x0013
  #@tpm_alg_rsassa 0x0014
  #@tpm_alg_rsaes  0x0015
  #@tpm_alg_rsapss 0x0016
  #@tpm_alg_oaep 0x0017
  #@tpm_alg_ecdsa  0x0018
  #@tpm_alg_ecdh 0x0019
  #@tpm_alg_ecdaa  0x001a
  #@tpm_alg_sm2  0x001b
  #@tpm_alg_ecschnorr  0x001c
  #@tpm_alg_ecmqv  0x001d
  #@tpm_alg_kdf1_sp800_56a 0x0020
  #@tpm_alg_kdf2 0x0021
  #@tpm_alg_kdf1_sp800_108 0x0022
  @tpm_alg_ecc  0x0023
  #@tpm_alg_symcipher 0x0025
  #@tpm_alg_camellia 0x0026
  #@tpm_alg_ctr  0x0040
  #@tpm_alg_ofb  0x0041
  #@tpm_alg_cbc  0x0042
  #@tpm_alg_cfb  0x0043
  #@tpm_alg_ecb  0x0044

  #@tpm_ecc_none 0x0000
  @tpm_ecc_nist_p192  0x0001
  @tpm_ecc_nist_p224  0x0002
  @tpm_ecc_nist_p256  0x0003
  @tpm_ecc_nist_p384  0x0004
  @tpm_ecc_nist_p521  0x0005
  #@tpm_ecc_bn_p256  0x0010
  #@tpm_ecc_bn_p638  0x0011
  #@tpm_ecc_sm2_p256 0x0020

  # from https://trustedcomputinggroup.org/resource/vendor-id-registry/
  # version 1.01
  @tpm_manufacturer_ids [
    "id:414D4400", # AMD
    "id:41544D4C", # Atmel
    "id:4252434D", # Broadcom
    "id:48504500", # HPE
    "id:49424d00", # IBM
    "id:49465800", # Infineon
    "id:494E5443", # Intel
    "id:4C454E00", # Lenovo
    "id:4D534654", # Microsoft
    "id:4E534D20", # National Semiconductor
    "id:4E545A00", # Nationz
    "id:4E544300", # Nuvoton Technology
    "id:51434F4D", # Qualcomm
    "id:534D5343", # SMSC
    "id:53544D20", # ST Microelectronics
    "id:534D534E", # Samsung
    "id:534E5300", # Sinosun
    "id:54584E00", # Texas Instruments
    "id:57454300", # Winbond
    "id:524F4343", # Fuzhouk Rockchip
    "id:474F4F47"  # Google,
  ]
  ++ ["id:FFFFF1D0"] # fake ID for conformance tool testing, uncomment only for testing

  @impl Wax.AttestationStatementFormat

  def verify(
    %{"x5c" => _} = att_stmt,
    auth_data,
    client_data_hash,
    %Wax.Challenge{attestation: "direct"} = challenge
  ) do
    with :ok <- valid_cbor?(att_stmt),
         :ok <- version_valid?(att_stmt),
         {:ok, cert_info} <- parse_cert_info(att_stmt["certInfo"]),
         {:ok, pub_area} <- parse_pub_area(att_stmt["pubArea"]),
         :ok <- verify_public_key(pub_area, auth_data),
         :ok <- cert_info_valid?(cert_info, auth_data, client_data_hash, att_stmt),
         :ok <- signature_valid?(att_stmt),
         :ok <- aik_cert_valid?(List.first(att_stmt["x5c"]), auth_data),
         {:ok, metadata_statement} <- attestation_path_valid?(att_stmt["x5c"], auth_data, challenge)
    do
      {:ok, {:basic, att_stmt["x5c"], metadata_statement}}
    else
      error ->
        error
    end
  end

  def verify(
    %{"ecdaaKeyId" => _},
    _auth_data,
    _client_data_hash,
    %Wax.Challenge{attestation: "direct"}
  ) do
    {:error, :attestation_tpm_unsupported_ecdaa_signature}
  end

  def verify(_attstmt, _auth_data, _client_data_hash, _challenge) do
    {:error, :invalid_attestation_conveyance_preference}
  end

  @spec valid_cbor?(Wax.Attestation.statement()) :: :ok | {:error, any()}
  defp valid_cbor?(att_stmt) do
    if is_binary(att_stmt["ver"])
    and is_integer(att_stmt["alg"])
    and is_binary(att_stmt["sig"])
    and is_list(att_stmt["x5c"])
    and is_binary(att_stmt["certInfo"])
    and is_binary(att_stmt["pubArea"])
    and length(Map.keys(att_stmt)) == 6
    do
      :ok
    else
      {:error, :attestation_tpm_invalid_cbor}
    end
  end

  @spec version_valid?(map()) :: :ok | {:error, any()}
  defp version_valid?(%{"ver" => "2.0"}), do: :ok
  defp version_valid?(_), do: {:error, :attestation_tpm_invalid_version}

  @spec parse_cert_info(binary) :: {:ok, map()} | {:error, any()}

  defp parse_cert_info(
    <<
      0xff544347::unsigned-big-integer-size(32),
      0x8017::unsigned-big-integer-size(16),
      qualified_signer_length::unsigned-big-integer-size(16),
      _qualified_signer::binary-size(qualified_signer_length),
      extra_data_length::unsigned-big-integer-size(16),
      extra_data::binary-size(extra_data_length),
      _clock_info::binary-size(17),
      _firmware_version::binary-size(8),
      attested_name_length::unsigned-big-integer-size(16),
      attested_name::binary-size(attested_name_length),
      attested_qualified_name_length::unsigned-big-integer-size(16),
      _attested_qualified_name::binary-size(attested_qualified_name_length)
    >>
  )
  do
    hash_length = attested_name_length - 2
    <<
      attested_name_digest::unsigned-big-integer-size(16),
      attested_name_hash::binary-size(hash_length)
    >> = attested_name

    {:ok, %{
      extra_data: extra_data,
      attested_name_digest: attested_name_digest,
      attested_name_hash: attested_name_hash,
    }}
  end

  defp parse_cert_info(_), do: {:error, :attestation_tpm_invalid_cert_info}

  @spec parse_pub_area(binary) :: {:ok, map()} | {:error, any()}

  defp parse_pub_area(
    <<
      @tpm_alg_rsa::unsigned-big-integer-size(16),
      name_alg::unsigned-big-integer-size(16),
      _object_attributes::binary-size(4),
      auth_policy_length::unsigned-big-integer-size(16),
      _auth_policy::binary-size(auth_policy_length),
      @tpm_alg_null::unsigned-big-integer-size(16), # symmetric
      _alg_rsa_scheme::unsigned-big-integer-size(16),
      _alg_rsa_key_bits::unsigned-big-integer-size(16),
      alg_rsa_exponent::unsigned-big-integer-size(32),
      unique_length::unsigned-big-integer-size(16),
      unique::unsigned-big-integer-size(unique_length)-unit(8)
    >>) do
    cert_info = {:ok, %{
      type: :rsa,
      name_alg: name_alg,
      exponent:
        if alg_rsa_exponent == 0 do
          65537 # default value if 0
        else
          alg_rsa_exponent
        end,
      unique_length: unique_length,
      modulus: unique}
    }

    Logger.debug("#{__MODULE__}: decoded cert_info: #{inspect(cert_info)}")

    cert_info
  end

  defp parse_pub_area(
    <<
      @tpm_alg_ecc::unsigned-big-integer-size(16),
      name_alg::unsigned-big-integer-size(16),
      _object_attributes::binary-size(4),
      auth_policy_length::unsigned-big-integer-size(16),
      _auth_policy::binary-size(auth_policy_length),
      @tpm_alg_null::unsigned-big-integer-size(16), # symmetric
      _alg_ecc_scheme::unsigned-big-integer-size(16),
      alg_ecc_curve_id::unsigned-big-integer-size(16),
      @tpm_alg_null::unsigned-big-integer-size(16), # kdf
      _unique_length::unsigned-big-integer-size(16),
      unique_x_length::unsigned-big-integer-size(16),
      unique_x::binary-size(unique_x_length),
      unique_y_length::unsigned-big-integer-size(16),
      unique_y::binary-size(unique_y_length),
    >>) do
    pub_area = {:ok, %{
      type: :ecc,
      name_alg: name_alg,
      curve: to_erlang_curve(alg_ecc_curve_id),
      x: unique_x,
      y: unique_y}
    }

    Logger.debug("#{__MODULE__}: decoded pub_area: #{inspect(pub_area)}")

    pub_area
  end

  defp parse_pub_area(_), do: {:error, :attestation_tpm_invalid_pub_area}

  @spec verify_public_key(map(), Wax.AuthenticatorData.t()) :: :ok | {:error, any()}

  defp verify_public_key(pub_area, auth_data) do
    pub_area_erlang_public_key = to_erlang_public_key(pub_area)

    auth_data_erlang_public_key =
      Wax.CoseKey.to_erlang_public_key(auth_data.attested_credential_data.credential_public_key)

    Logger.debug("#{__MODULE__}: verifying public keys, " <>
      "pub_area: #{inspect(pub_area_erlang_public_key)} ; " <>
      "auth_data: #{inspect(auth_data_erlang_public_key)}")

    if pub_area_erlang_public_key == auth_data_erlang_public_key do
      :ok
    else
      {:error, :attestation_tpm_public_key_mismatch}
    end
  end

  @spec cert_info_valid?(map(), Wax.AuthenticatorData.t(), Wax.ClientData.hash(), map())
    :: :ok | {:error, any()}

  defp cert_info_valid?(
    cert_info,
    auth_data,
    client_data_hash,
    att_stmt) do
    # %{3 => val} is a pseudo cose key, 3 being the algorithm
    digest = Wax.CoseKey.to_erlang_digest(%{3 =>att_stmt["alg"]})

    att_to_be_signed = auth_data.raw_bytes <> client_data_hash

    pub_area_hash =
      cert_info[:attested_name_digest]
      |> name_alg_to_erlang_digest()
      |> :crypto.hash(att_stmt["pubArea"])

    Logger.debug("#{__MODULE__}: verifying cert_info is valid: digest: #{inspect(digest)} ; " <>
      "att to be signed: #{inspect(att_to_be_signed)} ; " <>
      "pub_area hash: #{inspect(pub_area_hash)}"
      )

    if cert_info[:extra_data] == :crypto.hash(digest, att_to_be_signed)
      and cert_info[:attested_name_hash] == pub_area_hash
    do
      :ok
    else
      {:error, :attestation_tpm_invalid_cert_info}
    end
  end

  @spec signature_valid?(map()) :: :ok | {:error, any()}
  defp signature_valid?(%{
    "certInfo" => cert_info,
    "sig" => sig,
    "x5c" => [leaf_cert | _],
    "alg" => cose_key_alg
  }) do
    public_key =
      leaf_cert
      |> X509.Certificate.from_der!()
      |> X509.Certificate.public_key()

    digest = Wax.CoseKey.to_erlang_digest(%{3 => cose_key_alg})

    if :public_key.verify(cert_info, digest, sig, public_key) do
      :ok
    else
      {:error, :attestation_tpm_invalid_signature}
    end
  end

  @spec aik_cert_valid?(binary(), Wax.AuthenticatorData.t()) :: :ok | {:error, any()}

  defp aik_cert_valid?(cert_der, auth_data) do
    cert = X509.Certificate.from_der!(cert_der)

    Logger.debug("#{__MODULE__}: verifying validity of aik certificate: #{inspect(cert)}")

    {:Validity, {:utcTime, valid_from}, {:utcTime, valid_to}} = X509.Certificate.validity(cert)

    {:Extension, {2, 5, 29, 37}, false, key_ext_vals} =
      X509.Certificate.extension(cert, :ext_key_usage)

    if Wax.Utils.Certificate.version(cert) == :v3
      and X509.Certificate.subject(cert) == {:rdnSequence, []}
      and parse_cert_utc_time(valid_from) < Wax.Utils.Timestamp.get_timestamp()
      and parse_cert_utc_time(valid_to) > Wax.Utils.Timestamp.get_timestamp()
      and get_tcpaTpmManufacturer_field(cert) in @tpm_manufacturer_ids
      and {2, 23, 133, 8, 3} in key_ext_vals
      and Wax.Utils.Certificate.basic_constraints_ext_ca_component(cert) == false
    do
      # checking if oid of id-fido-gen-ce-aaguid is present and, if so, aaguid
      case X509.Certificate.extension(cert, {1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}) do
        # the <<4, 16>> 2 bytes are the tag for ASN octet string (aaguid is embedded twice)
        # see also: https://www.w3.org/TR/2019/PR-webauthn-20190117/#packed-attestation-cert-requirements
        {:Extension, {1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, _, <<4, 16, aaguid::binary>>} ->
          if aaguid == auth_data.attested_credential_data.aaguid do
            :ok
          else
            {:error, :attestation_tpm_invalid_aik_cert}
          end

        nil ->
          :ok
      end
    else
      {:error, :attestation_tpm_invalid_certificate}
    end
  end

  @spec parse_cert_utc_time(charlist()) :: non_neg_integer()
  defp parse_cert_utc_time(datetime) do
    <<
      year::binary-size(2),
      month::binary-size(2),
      day::binary-size(2),
      hour::binary-size(2),
      minute::binary-size(2),
      second::binary-size(2),
      "Z"::utf8
    >> = :erlang.list_to_binary(datetime)

    year =
      case Integer.parse(year) do
        {year_int, _} when year_int >= 50 ->
          "19" <> year

        {year_int, _} when year_int < 50 ->
          "20" <> year
      end

    year <> "-" <> month <> "-" <> day <> "T" <> hour <> ":" <> minute <> ":" <> second <> "Z"
    |> DateTime.from_iso8601()
    |> elem(1)
    |> DateTime.to_unix()
  end

  @spec attestation_path_valid?([binary()], Wax.AuthenticatorData.t(), Wax.Challenge.t()) ::
  {:ok, Wax.Metadata.Statement.t()}
  | {:error, any()}

  defp attestation_path_valid?(der_list, auth_data, challenge) do
    case Wax.Metadata.get_by_aaguid(auth_data.attested_credential_data.aaguid, challenge) do
      %Wax.Metadata.Statement{attestation_root_certificates: arcs} = metadata_statement ->
        if Enum.any?(
          arcs,
          fn arc ->
            :public_key.pkix_path_validation(
              arc,
              [arc | Enum.reverse(der_list)],
              verify_fun: {&verify_fun/3, %{}}
            )
            |> case do
              {:ok, _} ->
                true

              {:error, _} ->
                false
            end
          end
        ) do
          {:ok, metadata_statement}
        else
          {:error, :attestation_tpm_no_attestation_root_certificate_found}
        end

      _ ->
        {:error, :attestation_tpm_no_attestation_metadata_statement_found}
    end
  end

  # specific verify function which accepts the Certificate Policies extension
  # without further verification. OTP <= 23.0-rc1 does not recognizes this extension
  # which can be marked as critical in TPM's outputs, which make the path validation
  # fail.
  @oid_cert_policies {2, 5, 29, 32}
  def verify_fun(_, {:extension, {:Extension, @oid_cert_policies, true, _}}, user_state) do
    {:valid, user_state}
  end

  def verify_fun(_, {:extension, _}, user_state) do
    {:unknown, user_state}
  end

  def verify_fun(_, :valid, user_state) do
    {:valid, user_state}
  end

  def verify_fun(_, :valid_peer, user_state) do
    {:valid, user_state}
  end

  def verify_fun(_, reason, _) do
    {:fail, reason}
  end

  @spec get_tcpaTpmManufacturer_field(any()) :: String.t()

  # the field looks like:
  # {:Extension, {2, 5, 29, 17}, true,
  #  [
  #    directoryName: {:rdnSequence,
  #     [
  #       [
  #         {:AttributeTypeAndValue, {2, 23, 133, 2, 3},
  #          <<12, 5, 105, 100, 58, 49, 51>>},
  #         {:AttributeTypeAndValue, {2, 23, 133, 2, 2}, "\f\aNPCT6xx"},
  #         {:AttributeTypeAndValue, {2, 23, 133, 2, 1}, "\f\vid:4E544300"}
  #       ]
  #     ]}
  #  ]}

  defp get_tcpaTpmManufacturer_field(cert) do
    {:Extension, {2, 5, 29, 17}, true, ext_val} =
      X509.Certificate.extension(cert, :subject_alt_name)

    directory_name_val =
      ext_val[:directoryName]
      |> elem(1)
      |> List.first()

    Enum.find(
      directory_name_val,
      fn
        {_, {2, 23, 133, 2, 1}, _} ->
          true

        _ ->
          false
      end
    )
    |> elem(2) 
    |> String.slice(2..-1)
  end

  @spec to_erlang_curve(non_neg_integer()) :: tuple()
  defp to_erlang_curve(@tpm_ecc_nist_p192), do: :pubkey_cert_records.namedCurves(:secp192r1)
  defp to_erlang_curve(@tpm_ecc_nist_p224), do: :pubkey_cert_records.namedCurves(:secp224r1)
  defp to_erlang_curve(@tpm_ecc_nist_p256), do: :pubkey_cert_records.namedCurves(:secp256r1)
  defp to_erlang_curve(@tpm_ecc_nist_p384), do: :pubkey_cert_records.namedCurves(:secp384r1)
  defp to_erlang_curve(@tpm_ecc_nist_p521), do: :pubkey_cert_records.namedCurves(:secp521r1)
  # these 3 curves seem unsupported by Erlang
  # defp to_erlang_curve(@tpm_ecc_bn_p256), do:
  # defp to_erlang_curve(@tpm_ecc_bn_p638), do:
  # defp to_erlang_curve(@tpm_ecc_sm2_p256), do:

  @spec to_erlang_public_key(map()) :: :public_key.public_key()

  defp to_erlang_public_key(%{type: :rsa, modulus: n, exponent: e}) do
    {:RSAPublicKey, n, e}
  end

  defp to_erlang_public_key(%{type: :ecc, curve: curve, x: x, y: y}) do
    {{:ECPoint, <<4>> <> x <> y}, {:namedCurve, curve}}
  end

  @spec name_alg_to_erlang_digest(non_neg_integer()) :: atom()
  defp name_alg_to_erlang_digest(@tpm_alg_sha1), do: :sha
  defp name_alg_to_erlang_digest(@tpm_alg_sha256), do: :sha256
  defp name_alg_to_erlang_digest(@tpm_alg_sha384), do: :sha384
  defp name_alg_to_erlang_digest(@tpm_alg_sha512), do: :sha512
end
