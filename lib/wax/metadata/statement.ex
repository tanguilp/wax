defmodule Wax.Metadata.Statement do
  @moduledoc """
  Structure representing a FIDO2 metadata statement

  Reference: [FIDO Metadata Statements](https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-metadata-statement-v1.2-rd-20171128.html#metadata-keys)

  Note that the following keys are not included in this module because of irrelevance:
  - legalHeader
  - alternativeDescriptions
  - tcDisplayPNGCharacteristics
  - icon
  - tc_display_content_type

  """

  use Bitwise

  @enforce_keys [
    :description,
    :authenticator_version,
    :upv,
    :assertion_scheme,
    :authentication_algorithm,
    :public_key_alg_and_encoding,
    :attestation_types,
    :user_verification_details,
    :key_protection,
    :matcher_protection,
    :attachment_hint,
    :is_second_factor_only,
    :tc_display,
    :attestation_root_certificates
  ]

  defstruct [
    :aaid,
    :aaguid,
    :attestation_certificate_key_identifiers,
    :description,
    :authenticator_version,
    :protocol_family,
    :upv,
    :assertion_scheme,
    :authentication_algorithm,
    :authentication_algorithms,
    :public_key_alg_and_encoding,
    :public_key_alg_and_encodings,
    :attestation_types,
    :user_verification_details,
    :key_protection,
    :is_key_restricted,
    :is_fresh_user_verification_required,
    :matcher_protection,
    :crypto_strength,
    :operating_env,
    :attachment_hint,
    :is_second_factor_only,
    :tc_display,
    :tc_display_content_type,
    :attestation_root_certificates,
    :ecdaa_trust_anchors,
    :supported_extensions
  ]

  @type t :: %__MODULE__{
    aaid: String.t(),
    aaguid: String.t(),
    attestation_certificate_key_identifiers: [String.t()],
    description: String.t(),
    authenticator_version: non_neg_integer(),
    protocol_family: String.t(),
    upv: [Wax.Metadata.Statement.UPV.t()],
    assertion_scheme: String.t(),
    authentication_algorithm: Wax.Metadata.Statement.authentication_algorithm(),
    authentication_algorithms: [Wax.Metadata.Statement.authentication_algorithm()],
    public_key_alg_and_encoding: Wax.Metadata.Statement.public_key_representation_format(),
    public_key_alg_and_encodings: [Wax.Metadata.Statement.public_key_representation_format()],
    attestation_types: [Wax.Metadata.Statement.attestation_type()],
    user_verification_details: [verification_method_and_combinations()],
    key_protection: [key_protection()],
    is_key_restricted: boolean(),
    is_fresh_user_verification_required: boolean(),
    matcher_protection: matcher_protection(), # far now all values exclude each other
    crypto_strength: non_neg_integer(),
    operating_env: String.t(),
    attachment_hint: [attachment_hint()],
    is_second_factor_only: boolean(),
    tc_display: [tc_display()],
    attestation_root_certificates: [:public_key.der_encoded()],
    ecdaa_trust_anchors: [Wax.Metadata.Statement.EcdaaTrustAnchor],
    supported_extensions: [Wax.Metadata.Statement.ExtensionDescriptor]
  }

  @type authentication_algorithm ::
  :alg_sign_secp256r1_ecdsa_sha256_raw
  | :alg_sign_secp256r1_ecdsa_sha256_der
  | :alg_sign_rsassa_pss_sha256_raw
  | :alg_sign_rsassa_pss_sha256_der
  | :alg_sign_secp256k1_ecdsa_sha256_raw
  | :alg_sign_secp256k1_ecdsa_sha256_der
  | :alg_sign_sm2_sm3_raw
  | :alg_sign_rsa_emsa_pkcs1_sha256_raw
  | :alg_sign_rsa_emsa_pkcs1_sha256_der
  | :alg_sign_rsassa_pss_sha384_raw
  | :alg_sign_rsassa_pss_sha512_raw
  | :alg_sign_rsassa_pkcsv15_sha256_raw
  | :alg_sign_rsassa_pkcsv15_sha384_raw
  | :alg_sign_rsassa_pkcsv15_sha512_raw
  | :alg_sign_rsassa_pkcsv15_sha1_raw
  | :alg_sign_secp384r1_ecdsa_sha384_raw
  | :alg_sign_secp521r1_ecdsa_sha512_raw
  | :alg_sign_ed25519_eddsa_sha256_raw
  | :alg_sign_ed25519_eddsa_sha512_raw

  @type public_key_representation_format ::
  :alg_key_ecc_x962_raw
  | :alg_key_ecc_x962_der
  | :alg_key_rsa_2048_raw
  | :alg_key_rsa_2048_der
  | :alg_key_cose

  @type attestation_type ::
  :tag_attestation_basic_full
  | :tag_attestation_basic_surrogate
  | :tag_attestation_ecdaa
  | :tag_attestation_attca

  @type verification_method_and_combinations ::
    [Wax.Metadata.Statement.VerificationMethodDescriptor.t()]

  defmodule UPV do
    @enforce_keys [:minor, :major]

    defstruct [:minor, :major]

    @type t :: %__MODULE__{
      minor: non_neg_integer(),
      major: non_neg_integer(),
    }
  end

  defmodule VerificationMethodDescriptor do
    @enforce_keys [:user_verification]

    defstruct [
      :user_verification,
      :code_accuracy_descriptor,
      :biometric_accuracy_descriptor,
      :pattern_accuracy_descriptor
    ]

    @type t :: %__MODULE__{
      user_verification: Wax.Metadata.Statement.user_verification_method(),
      code_accuracy_descriptor:
        Wax.Metadata.Statement.VerificationMethodDescriptor.CodeAccuracyDescriptor.t(),
      biometric_accuracy_descriptor:
        Wax.Metadata.Statement.VerificationMethodDescriptor.BiometricAccuracyDescriptor.t(),
      pattern_accuracy_descriptor:
        Wax.Metadata.Statement.VerificationMethodDescriptor.PatternAccuracyDescriptor.t()
    }

    defmodule CodeAccuracyDescriptor do
      @enforce_keys [:base, :min_length]

      defstruct [:base, :min_length, :max_retries, :block_slowdown]

      @type t :: %__MODULE__{
        base: non_neg_integer(),
        min_length: non_neg_integer(),
        max_retries: non_neg_integer(),
        block_slowdown: non_neg_integer()
      }
    end

    defmodule BiometricAccuracyDescriptor do
      defstruct [:far, :frr, :eer, :faar, :max_reference_data_sets, :max_retries, :block_slowdown]

      @type t :: %__MODULE__{
        far: float(),
        frr: float(),
        eer: float(),
        faar: float(),
        max_reference_data_sets: non_neg_integer(),
        max_retries: non_neg_integer(),
        block_slowdown: non_neg_integer()
      }
    end

    defmodule PatternAccuracyDescriptor do
      @enforce_keys [:min_complexity]

      defstruct [:min_complexity, :max_retries, :block_slowdown]

      @type t :: %__MODULE__{
        min_complexity: non_neg_integer(),
        max_retries: non_neg_integer(),
        block_slowdown: non_neg_integer()
      }
    end
  end

  @type user_verification_method ::
  :user_verify_presence_internal
  | :user_verify_fingerprint_internal
  | :user_verify_passcode_internal
  | :user_verify_voiceprint_internal
  | :user_verify_faceprint_internal
  | :user_verify_location_internal
  | :user_verify_eyeprint_internal
  | :user_verify_pattern_internal
  | :user_verify_handprint_internal
  | :user_verify_passcode_external
  | :user_verify_pattern_external
  | :user_verify_none
  | :user_verify_all

  @type key_protection ::
  :key_protection_software
  | :key_protection_hardware
  | :key_protection_tee
  | :key_protection_secure_element
  | :key_protection_remote_handle

  @type matcher_protection ::
  :matcher_protection_software
  | :matcher_protection_tee
  | :matcher_protection_on_chip

  @type attachment_hint ::
  :attachment_hint_internal
  | :attachment_hint_external
  | :attachment_hint_wired
  | :attachment_hint_wireless
  | :attachment_hint_nfc
  | :attachment_hint_bluetooth
  | :attachment_hint_network
  | :attachment_hint_ready
  | :attachment_hint_wifi_direct

  @type tc_display ::
  :transaction_confirmation_display_any
  | :transaction_confirmation_display_privileged_software
  | :transaction_confirmation_display_tee
  | :transaction_confirmation_display_hardware
  | :transaction_confirmation_display_remote

  defmodule EcdaaTrustAnchor do
    @enforce_keys [
      :x,
      :y,
      :c,
      :sx,
      :sy,
      :g1_curve
    ]

    defstruct [
      :x,
      :y,
      :c,
      :sx,
      :sy,
      :g1_curve
    ]

    @type t :: %__MODULE__{
      x: String.t(),
      y: String.t(),
      c: String.t(),
      sx: String.t(),
      sy: String.t(),
      g1_curve: String.t()
    }
  end

  defmodule ExtensionDescriptor do
    @enforce_keys [:id, :fail_if_unknown]

    defstruct [
      :id,
      :tag,
      :data,
      :fail_if_unknown
    ]

    @type t :: %__MODULE__{
      id: String.t(),
      tag: non_neg_integer(),
      data: String.t(),
      fail_if_unknown: boolean()
    }
  end

  @doc false

  @spec from_json(map() | Keyword.t() | nil) :: {:ok, t()} | {:error, any()}
  def from_json(json) do
    try do
      {:ok, from_json!(json)}
    rescue
      e ->
        {:error, e}
    end
  end

  @spec from_json!(map() | Keyword.t() | nil) :: t()
  def from_json!(%{} = json) do
    %__MODULE__{
      aaid: json["aaid"],
      aaguid: json["aaguid"],
      attestation_certificate_key_identifiers: json["attestationCertificateKeyIdentifiers"],
      description: json["description"],
      authenticator_version: json["authenticatorVersion"],
      protocol_family: json["protocolFamily"],
      upv: Enum.map(
        json["upv"] || [],
        fn %{"minor" => minor, "major" => major} ->
          %Wax.Metadata.Statement.UPV{
            major: major,
            minor: minor
          }
        end
      ),
      assertion_scheme: json["assertionScheme"],
      authentication_algorithm: Enum.map(
        json["authenticationAlgorithms"] || [],
        fn alg ->
          authentication_algorithm(alg)
        end
      ) |> Enum.at(0),
      authentication_algorithms: Enum.map(
        json["authenticationAlgorithms"] || [],
        fn alg ->
          authentication_algorithm(alg)
        end
      ),
      public_key_alg_and_encoding:  Enum.map(
        json["publicKeyAlgAndEncodings"] || [],
        fn keyalg ->
          public_key_representation_format(keyalg)
        end
      ) |> Enum.at(0),
      public_key_alg_and_encodings: Enum.map(
        json["publicKeyAlgAndEncodings"] || [],
        fn keyalg ->
          public_key_representation_format(keyalg)
        end
      ),
      attestation_types: Enum.map(
        json["attestationTypes"],
        fn att_type ->
          attestation_type(att_type)
        end
      ),
      user_verification_details: Enum.map(
        json["userVerificationDetails"],
        fn list ->
          Enum.map(
            list,
            fn uvd ->
              %Wax.Metadata.Statement.VerificationMethodDescriptor{
                user_verification: user_verification_method(uvd["userVerificationMethod"]),
                code_accuracy_descriptor: code_accuracy_descriptor(uvd["caDesc"]),
                biometric_accuracy_descriptor: biometric_accuracy_descriptor(uvd["baDesc"]),
                pattern_accuracy_descriptor: pattern_accuracy_descriptor(uvd["paDesc"])
              }
            end
          )
        end
      ),
      key_protection: key_protection(json["keyProtection"]),
      is_key_restricted: json["isKeyRestricted"],
      is_fresh_user_verification_required: json["isFreshUserVerificationRequired"],
      matcher_protection: Enum.map(
        json["matcherProtection"],
        fn prot ->
          matcher_protection(prot)
        end
      ) |> Enum.at(0),
      crypto_strength: json["cryptoStrength"],
      operating_env: json["operatingEnv"],
      attachment_hint: attachment_hint(json["attachmentHint"]),
      is_second_factor_only: json["isSecondFactorOnly"],
      tc_display: tc_display(json["tcDisplay"]),
      attestation_root_certificates: Enum.map(
        json["attestationRootCertificates"],
        fn
          b64_cert ->
            Base.decode64!(b64_cert, ignore: :whitespace)
        end
      ),
      ecdaa_trust_anchors: Enum.map(
        json["ecdaaTrustAnchors"] || [],
        fn map ->
          %Wax.Metadata.Statement.EcdaaTrustAnchor{
            x: map["X"],
            y: map["Y"],
            c: map["c"],
            sx: map["sx"],
            sy: map["sy"],
            g1_curve: map["G1Curve"]
          }
        end
      ),
      supported_extensions: Enum.map(
        json["supportedExtensions"] || [],
        fn map ->
          %Wax.Metadata.Statement.ExtensionDescriptor{
            id: map["id"],
            tag: map["tag"],
            data: map["data"],
            fail_if_unknown: map["fail_if_unknown"]
          }
        end
      )
    }
  end

  @spec authentication_algorithm(String.t()) :: authentication_algorithm()
  defp authentication_algorithm("secp256r1_ecdsa_sha256_raw"), do: :alg_sign_secp256r1_ecdsa_sha256_raw
  defp authentication_algorithm("secp256r1_ecdsa_sha256_der"), do: :alg_sign_secp256r1_ecdsa_sha256_der
  defp authentication_algorithm("rsassa_pss_sha258_raw"),      do: :alg_sign_rsassa_pss_sha258_raw
  defp authentication_algorithm("rsassa_pss_sha256_der"),      do: :alg_sign_rsassa_pss_sha256_der
  defp authentication_algorithm("secp256k1_ecdsa_sha256_raw"), do: :alg_sign_secp256k1_ecdsa_sha256_raw
  defp authentication_algorithm("secp256k1_ecdsa_sha256_der"), do: :alg_sign_secp256k1_ecdsa_sha256_der
  defp authentication_algorithm("sm2_sm3_raw"),                do: :alg_sign_sm2_sm3_raw
  defp authentication_algorithm("rsa_emsa_pkcs1_sha256_raw"),  do: :alg_sign_rsa_emsa_pkcs1_sha256_raw
  defp authentication_algorithm("rsa_emsa_pkcs1_sha256_der"),  do: :alg_sign_rsa_emsa_pkcs1_sha256_der
  defp authentication_algorithm("rsassa_pss_sha384_raw"),      do: :alg_sign_rsassa_pss_sha384_raw
  defp authentication_algorithm("rsassa_pss_sha512_raw"),      do: :alg_sign_rsassa_pss_sha512_raw
  defp authentication_algorithm("rsassa_pkcsv15_sha256_raw"),  do: :alg_sign_rsassa_pkcsv15_sha256_raw
  defp authentication_algorithm("rsassa_pkcsv15_sha384_raw"),  do: :alg_sign_rsassa_pkcsv15_sha384_raw
  defp authentication_algorithm("rsassa_pkcsv15_sha512_raw"),  do: :alg_sign_rsassa_pkcsv15_sha512_raw
  defp authentication_algorithm("rsassa_pkcsv15_sha1_raw"),    do: :alg_sign_rsassa_pkcsv15_sha1_raw
  defp authentication_algorithm("secp384r1_ecdsa_sha384_raw"), do: :alg_sign_secp384r1_ecdsa_sha384_raw
  defp authentication_algorithm("secp521r1_ecdsa_sha512_raw"), do: :alg_sign_secp521r1_ecdsa_sha512_raw
  defp authentication_algorithm("ed25519_eddsa_sha256_raw"),   do: :alg_sign_ed25519_eddsa_sha256_raw
  defp authentication_algorithm("ed25519_eddsa_sha512_raw"),   do: :alg_sign_ed25519_eddsa_sha512_raw

  @spec public_key_representation_format(non_neg_integer()) :: public_key_representation_format()
  defp public_key_representation_format("ecc_x962_raw"), do: :alg_key_ecc_x962_raw
  defp public_key_representation_format("ecc_x962_der"), do: :alg_key_ecc_x962_der
  defp public_key_representation_format("rsa_2048_raw"), do: :alg_key_rsa_2048_raw
  defp public_key_representation_format("rsa_2048_der"), do: :alg_key_rsa_2048_der
  defp public_key_representation_format("cose"),         do: :alg_key_cose

  @spec attestation_type(non_neg_integer()) :: attestation_type()
  defp attestation_type("basic_full"), do: :tag_attestation_basic_full
  defp attestation_type("basic_surrogate"), do: :tag_attestation_basic_surrogate
  defp attestation_type("ecdaa"), do: :tag_attestation_ecdaa
  defp attestation_type("attca"), do: :tag_attestation_attca

  @spec user_verification_method(non_neg_integer()) :: user_verification_method()
  defp user_verification_method("presence_internal"),    do: :user_verify_presence_internal
  defp user_verification_method("fingerprint_internal"), do: :user_verify_fingerprint_internal
  defp user_verification_method("passcode_internal"),    do: :user_verify_passcode_internal
  defp user_verification_method("voiceprint_internal"),  do: :user_verify_voiceprint_internal
  defp user_verification_method("faceprint_internal"),   do: :user_verify_faceprint_internal
  defp user_verification_method("location_internal"),    do: :user_verify_location_internal
  defp user_verification_method("eyeprint_internal"),    do: :user_verify_eyeprint_internal
  defp user_verification_method("pattern_internal"),     do: :user_verify_pattern_internal
  defp user_verification_method("handprint_internal"),   do: :user_verify_handprint_internal
  defp user_verification_method("passcode_external"),    do: :user_verify_passcode_external
  defp user_verification_method("pattern_external"),     do: :user_verify_pattern_external
  defp user_verification_method("none"),                 do: :user_verify_none
  defp user_verification_method("all"),                  do: :user_verify_all

  @spec code_accuracy_descriptor(map()) ::
    Wax.Metadata.Statement.VerificationMethodDescriptor.CodeAccuracyDescriptor.t()

  defp code_accuracy_descriptor(nil), do: nil
  defp code_accuracy_descriptor(map)
  do
    %Wax.Metadata.Statement.VerificationMethodDescriptor.CodeAccuracyDescriptor{
      base: map["base"],
      min_length: map["minLength"],
      max_retries: map["maxRetries"],
      block_slowdown: map["blockSlowdown"]
    }
  end

  @spec biometric_accuracy_descriptor(map()) ::
    Wax.Metadata.Statement.VerificationMethodDescriptor.BiometricAccuracyDescriptor.t()

  defp biometric_accuracy_descriptor(nil), do: nil
  defp biometric_accuracy_descriptor(map)
  do
    %Wax.Metadata.Statement.VerificationMethodDescriptor.BiometricAccuracyDescriptor{
      far: map["FAR"],
      frr: map["FRR"],
      eer: map["EER"],
      faar: map["FAAR"],
      max_reference_data_sets: map["maxReferenceDataSets"],
      max_retries: map["maxRetries"],
      block_slowdown: map["blockSlowdown"]
    }
  end

  @spec pattern_accuracy_descriptor(map()) ::
    Wax.Metadata.Statement.VerificationMethodDescriptor.PatternAccuracyDescriptor.t()

  defp pattern_accuracy_descriptor(nil), do: nil
  defp pattern_accuracy_descriptor(map)
  do
    %Wax.Metadata.Statement.VerificationMethodDescriptor.PatternAccuracyDescriptor{
      min_complexity: map["minComplexity"],
      max_retries: map["maxRetries"],
      block_slowdown: map["blockSlowdown"]
    }
  end

  @spec key_protection(non_neg_integer()) :: [key_protection()]
  defp key_protection(kp) do
    []
    |> key_protected_software(kp)
    |> key_protected_hardware(kp)
    |> key_protected_tee(kp)
    |> key_protected_secure_element(kp)
    |> key_protected_remote_handle(kp)
  end

  @spec key_protected_software([key_protection()], non_neg_integer()) :: [key_protection]

  defp key_protected_software(kp_list, kp) when (kp &&& 0x0001) > 0
  do
    [:key_protection_software | kp_list]
  end

  defp key_protected_software(kp_list, _), do: kp_list

  @spec key_protected_hardware([key_protection()], non_neg_integer()) :: [key_protection]

  defp key_protected_hardware(kp_list, kp) when (kp &&& 0x0002) > 0
  do
    [:key_protection_hardware | kp_list]
  end

  defp key_protected_hardware(kp_list, _), do: kp_list

  @spec key_protected_tee([key_protection()], non_neg_integer()) :: [key_protection]

  defp key_protected_tee(kp_list, kp) when (kp &&& 0x0004) > 0
  do
    [:key_protection_tee | kp_list]
  end

  defp key_protected_tee(kp_list, _), do: kp_list

  @spec key_protected_secure_element([key_protection()], non_neg_integer()) :: [key_protection]

  defp key_protected_secure_element(kp_list, kp) when (kp &&& 0x0008) > 0
  do
    [:key_protection_secure_element | kp_list]
  end

  defp key_protected_secure_element(kp_list, _), do: kp_list

  @spec key_protected_remote_handle([key_protection()], non_neg_integer()) :: [key_protection]

  defp key_protected_remote_handle(kp_list, kp) when (kp &&& 0x0010) > 0
  do
    [:key_protection_remote_handle | kp_list]
  end

  defp key_protected_remote_handle(kp_list, _), do: kp_list

  @spec matcher_protection(non_neg_integer()) :: matcher_protection()

  defp matcher_protection("software"), do: :matcher_protection_software
  defp matcher_protection("tee"), do: :matcher_protection_tee
  defp matcher_protection("on_chip"), do: :matcher_protection_on_chip

  @spec attachment_hint(non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint(ah)
  do
    []
    |> attachment_hint_internal(ah)
    |> attachment_hint_external(ah)
    |> attachment_hint_wired(ah)
    |> attachment_hint_wireless(ah)
    |> attachment_hint_nfc(ah)
    |> attachment_hint_bluetooth(ah)
    |> attachment_hint_network(ah)
    |> attachment_hint_ready(ah)
  end

  @spec attachment_hint_internal([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_internal(ah_list, ah) when (ah &&& 0x0001) > 0
  do
    [:attachment_hint_internal | ah_list]
  end

  defp attachment_hint_internal(ah_list, _), do: ah_list

  @spec attachment_hint_external([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_external(ah_list, ah) when (ah &&& 0x0002) > 0
  do
    [:attachment_hint_external | ah_list]
  end

  defp attachment_hint_external(ah_list, _), do: ah_list

  @spec attachment_hint_wired([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_wired(ah_list, ah) when (ah &&& 0x0004) > 0
  do
    [:attachment_hint_wired | ah_list]
  end

  defp attachment_hint_wired(ah_list, _), do: ah_list

  @spec attachment_hint_wireless([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_wireless(ah_list, ah) when (ah &&& 0x0008) > 0
  do
    [:attachment_hint_wireless | ah_list]
  end

  defp attachment_hint_wireless(ah_list, _), do: ah_list

  @spec attachment_hint_nfc([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_nfc(ah_list, ah) when (ah &&& 0x0010) > 0
  do
    [:attachment_hint_nfc | ah_list]
  end

  defp attachment_hint_nfc(ah_list, _), do: ah_list

  @spec attachment_hint_bluetooth([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_bluetooth(ah_list, ah) when (ah &&& 0x0020) > 0
  do
    [:attachment_hint_bluetooth | ah_list]
  end

  defp attachment_hint_bluetooth(ah_list, _), do: ah_list

  @spec attachment_hint_network([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_network(ah_list, ah) when (ah &&& 0x0040) > 0
  do
    [:attachment_hint_network | ah_list]
  end

  defp attachment_hint_network(ah_list, _), do: ah_list

  @spec attachment_hint_ready([attachment_hint()], non_neg_integer()) :: [attachment_hint()]

  defp attachment_hint_ready(ah_list, ah) when (ah &&& 0x0080) > 0
  do
    [:attachment_hint_ready | ah_list]
  end

  defp attachment_hint_ready(ah_list, ah) when (ah &&& 0x0100) > 0
  do
    [:attachment_hint_wifi_direct | ah_list]
  end

  defp attachment_hint_ready(ah_list, _), do: ah_list

  @spec tc_display(non_neg_integer()) :: [tc_display()]

  defp tc_display(tc)
  do
    []
    |> tc_display_any(tc)
    |> tc_display_privileged_software(tc)
    |> tc_display_tee(tc)
    |> tc_display_hardware(tc)
    |> tc_display_remote(tc)
  end

  @spec tc_display_any([tc_display()], non_neg_integer()) :: [tc_display()]

  defp tc_display_any(tc_list, tc) when (tc &&& 0x0001) > 0
  do
    [:transaction_confirmation_display_any | tc_list]
  end

  defp tc_display_any(tc_list, _), do: tc_list

  @spec tc_display_privileged_software([tc_display()], non_neg_integer()) :: [tc_display()]

  defp tc_display_privileged_software(tc_list, tc) when (tc &&& 0x0002) > 0
  do
    [:transaction_confirmation_display_privileged_software | tc_list]
  end

  defp tc_display_privileged_software(tc_list, _), do: tc_list

  @spec tc_display_tee([tc_display()], non_neg_integer()) :: [tc_display()]

  defp tc_display_tee(tc_list, tc) when (tc &&& 0x0004) > 0
  do
    [:transaction_confirmation_display_tee | tc_list]
  end

  defp tc_display_tee(tc_list, _), do: tc_list

  @spec tc_display_hardware([tc_display()], non_neg_integer()) :: [tc_display()]

  defp tc_display_hardware(tc_list, tc) when (tc &&& 0x0008) > 0
  do
    [:transaction_confirmation_display_hardware | tc_list]
  end

  defp tc_display_hardware(tc_list, _), do: tc_list

  @spec tc_display_remote([tc_display()], non_neg_integer()) :: [tc_display()]

  defp tc_display_remote(tc_list, tc) when (tc &&& 0x0010) > 0
  do
    [:transaction_confirmation_display_remote | tc_list]
  end

  defp tc_display_remote(tc_list, _), do: tc_list
end
