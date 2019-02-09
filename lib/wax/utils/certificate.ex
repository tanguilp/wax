defmodule Wax.Utils.Certificate do
  @moduledoc false 

  @spec version(X509.Certificate.t()) :: atom()

  def version(
    {:OTPCertificate, {:OTPTBSCertificate, version, _, _, _, _, _, _, _, _, _}, _, _}
  ) do
    version
  end

  @spec subject_component_value(X509.Certificate.t(), String.t()) :: String.t() | nil

  #FIXME: that's a hack. Rewrite this function without using to_string. Requires
  # knowledge of X509 RDNs though

  def subject_component_value(cert, searched) do
    subject_str =
      cert
      |> X509.Certificate.subject()
      |> X509.RDNSequence.to_string()
      # e.g.  "/C=CN/O=Feitian Technologies/OU=Authenticator Attestation/CN=FT BioPass FIDO2 USB"

    Enum.find_value(
      String.split(subject_str, "/"),
      fn comp ->
        case String.split(comp, "=") do
          [^searched, value] ->
            value

          _ ->
            nil
        end
      end
    )
  end

  @spec basic_constraints_ext_ca_component(X509.Certificate.t()) :: boolean()

  def basic_constraints_ext_ca_component(cert) do
    {:Extension, {2, 5, 29, 19}, _, {:BasicConstraints, ca_component, _}} =
      X509.Certificate.extension(cert, :basic_constraints)

    ca_component
  end

  @spec attestation_certificate_key_identifier(binary()) :: binary()

  # we take the raw certificate into parameter because we'll convert it to TBSCertificate
  # insted of OTPTBSCertificate
  def attestation_certificate_key_identifier(cert_der) do
    {:Certificate,
      {:TBSCertificate, _, _, _, _, _, _,
        {:SubjectPublicKeyInfo, _, subject_public_key}, _, _, _},
      _, _} = X509.Certificate.from_der!(cert_der, :Certificate)

    :crypto.hash(:sha, subject_public_key)
  end

  @spec signature_algorithm(X509.Certificate.t()) :: tuple()

  def signature_algorithm(cert) do
    {:OTPCertificate,
      {:OTPTBSCertificate, :v3, _,
        {:SignatureAlgorithm, sig_alg_1, _},
        _,
        _,
        _,
        _, _, _,
        _}, {:SignatureAlgorithm, sig_alg_2, _},
      _} = cert

    if sig_alg_1 == sig_alg_2 do
      sig_alg_1
    else
      raise "Different sig algs in the same certificate"
    end
  end
end
