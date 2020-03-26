defmodule Wax.AttestationStatementFormat.Packed do
  require Logger

  @moduledoc false

  @behaviour Wax.AttestationStatementFormat

  # from https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements
  # on the 27/01/2019
  @iso_3166_codes [
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX",
    "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
    "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI",
    "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK",
    "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO",
    "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR",
    "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM",
    "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM",
    "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU",
    "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP",
    "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG",
    "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL",
    "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB",
    "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST",
    "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "IS", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE",
    "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
  ]

  @impl Wax.AttestationStatementFormat
  def verify(
    %{"x5c" => _} = att_stmt,
    auth_data,
    client_data_hash,
    %Wax.Challenge{attestation: "direct"} = challenge
  ) do
    with :ok <- valid_cbor?(att_stmt),
         :ok <- valid_attestation_certificate?(List.first(att_stmt["x5c"]), auth_data),
         :ok <- valid_x5c_signature?(att_stmt, auth_data, client_data_hash),
         :ok <- attestation_path_valid?(att_stmt["x5c"], auth_data, challenge)
    do
      {:ok,
        {
          determine_attestation_type(auth_data, challenge),
          att_stmt["x5c"],
          Wax.Metadata.get_by_aaguid(auth_data.attested_credential_data.aaguid, challenge)
        }
      }
    end
  end

  def verify(%{"x5c" => _}, _auth_data, _client_data_hash, _challenge) do
    {:error, :invalid_attestation_conveyance_preference}
  end

  def verify(
    %{"ecdaaKeyId" => _},
    _auth_data,
    _client_hash_data,
    %Wax.Challenge{attestation: "direct"}
  ) do
    {:error, :attestation_packed_unimplemented}
  end

  # self-attestation case

  def verify(att_stmt, auth_data, client_data_hash, _challenge) do
    with :ok <- valid_cbor?(att_stmt),
         :ok <- algs_match?(att_stmt, auth_data),
         :ok <- valid_self_signature?(att_stmt, auth_data, client_data_hash)
    do
      {:ok, {:self, nil, nil}}
    else
      error ->
        error
    end
  end

  @spec valid_cbor?(Wax.Attestation.statement()) :: :ok | {:error, any()}

  defp valid_cbor?(%{"x5c" => _} = att_stmt) do
    if is_integer(att_stmt["alg"])
    and is_binary(att_stmt["sig"])
    and is_list(att_stmt["x5c"])
    and length(Map.keys(att_stmt)) == 3
    do
      :ok
    else
      {:error, :attestation_packed_invalid_cbor}
    end
  end

  defp valid_cbor?(att_stmt) do
    if is_integer(att_stmt["alg"])
    and is_binary(att_stmt["sig"])
    and length(Map.keys(att_stmt)) == 2
    do
      :ok
    else
      {:error, :attestation_packed_invalid_cbor}
    end
  end

  @spec valid_x5c_signature?(map(), Wax.AuthenticatorData.t(), Wax.ClientData.hash())
    :: :ok | {:error, any()}

  defp valid_x5c_signature?(att_stmt, auth_data, client_data_hash) do
    pub_key =
      att_stmt["x5c"]
      |> List.first()
      |> X509.Certificate.from_der!()
      |> X509.Certificate.public_key()

    digest = Wax.CoseKey.to_erlang_digest(%{3 => att_stmt["alg"]})

    Logger.debug("#{__MODULE__}: verifying signature with public key #{inspect(pub_key)} " <>
      "(digest: #{inspect(digest)})")

    if :public_key.verify(auth_data.raw_bytes <> client_data_hash,
                          digest,
                          att_stmt["sig"],
                          pub_key)
    do
      :ok
    else
      {:error, :attestation_packed_invalid_signature}
    end
  end

  @spec valid_self_signature?(map(), Wax.AuthenticatorData.t(), Wax.ClientData.hash())
    :: :ok | {:error, any()}

  defp valid_self_signature?(att_stmt, auth_data, client_data_hash) do
    Wax.CoseKey.verify(
      auth_data.raw_bytes <> client_data_hash,
      auth_data.attested_credential_data.credential_public_key,
      att_stmt["sig"]
    )
    |> case do
      :ok ->
        :ok

      {:error, :invalid_signature} ->
        {:error, :attestation_packed_invalid_signature}
    end
  end

  @spec algs_match?(map(), Wax.AuthenticatorData.t()) :: :ok | {:error, any()}

  defp algs_match?(att_stmt, auth_data) do
    if att_stmt["alg"] == auth_data.attested_credential_data.credential_public_key[3] do
      :ok
    else
      {:attestation_packed_algs_mismatch}
    end
  end

  @spec valid_attestation_certificate?(binary(), Wax.AuthenticatorData.t()) ::
  :ok
  | {:error, any()}

  defp valid_attestation_certificate?(cert_der, auth_data) do
    cert = X509.Certificate.from_der!(cert_der)

    Logger.debug("#{__MODULE__}: verifying certificate info of #{inspect(cert)}")

    subject = X509.Certificate.subject(cert)

    # here we interpret the specification "Subject field MUST be set to:"
    # (https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements)
    # as if only one value is authorized, per attribute
    [subject_c] = X509.RDNSequence.get_attr(subject, "C")
    [subject_o] = X509.RDNSequence.get_attr(subject, "O")
    [subject_ou] = X509.RDNSequence.get_attr(subject, "OU")
    [subject_cn] = X509.RDNSequence.get_attr(subject, "CN")

    if Wax.Utils.Certificate.version(cert) == :v3
      and subject_c in @iso_3166_codes
      and is_binary(subject_o) and subject_o != ""
      and subject_ou == "Authenticator Attestation"
      and is_binary(subject_cn) and subject_cn != ""
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
            {:error, :attestation_packed_invalid_attestation_cert}
          end

        nil ->
          :ok
      end
    else
      {:error, :attestation_packed_invalid_attestation_cert}
    end
  rescue
    MatchError ->
      {:error, :attestation_packed_invalid_attestation_subject_field}
  end

  @spec determine_attestation_type(Wax.AuthenticatorData.t(), Wax.Challenge.t()) :: Wax.Attestation.type()

  defp determine_attestation_type(auth_data, challenge) do
    aaguid = auth_data.attested_credential_data.aaguid

    Logger.debug("#{__MODULE__}: determining attestation type for aaguid=#{inspect(aaguid)}")

    case Wax.Metadata.get_by_aaguid(aaguid, challenge) do
      nil ->
        :uncertain

      metadata_statement ->
        if :tag_attestation_basic_full in metadata_statement.attestation_types do
          :basic
        else
          if :tag_attestation_attca in metadata_statement.attestation_types do
            :attca
          else
            :uncertain
          end
        end
    end
  end

  @spec attestation_path_valid?([binary()], Wax.AuthenticatorData.t(), Wax.Challenge.t()) ::
  :ok
  | {:error, any()}

  defp attestation_path_valid?(
    der_list,
    auth_data,
    %Wax.Challenge{verify_trust_root: true} = challenge
  ) do
    case Wax.Metadata.get_by_aaguid(auth_data.attested_credential_data.aaguid, challenge) do
      %Wax.Metadata.Statement{attestation_root_certificates: arcs} ->
        if Enum.any?(
          arcs,
          fn arc ->
            case :public_key.pkix_path_validation(arc,
                                                  [arc | Enum.reverse(der_list)],
                                                  [])
            do
              {:ok, _} ->
                true

              {:error, _} ->
                false
            end
          end
        ) do
          :ok
        else
          {:error, :attestation_packed_no_attestation_root_certificate_found}
        end

      _ ->
        {:error, :attestation_packed_no_attestation_metadata_statement_found}
    end
  end

  defp attestation_path_valid?(_, _, %Wax.Challenge{verify_trust_root: false}) do
    :ok
  end
end
