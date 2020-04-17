defmodule Wax.Utils.Certificate do
  @moduledoc false

  @spec version(X509.Certificate.t()) :: atom()

  def version(
    {:OTPCertificate, {:OTPTBSCertificate, version, _, _, _, _, _, _, _, _, _}, _, _}
  ) do
    version
  end

  @spec serial_number(X509.Certificate.t()) :: integer()

  def serial_number(
    {:OTPCertificate, {:OTPTBSCertificate, _, serial_number, _, _, _, _, _, _, _, _}, _, _}
  ) do
    serial_number
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

  @spec public_key_algorithm(X509.Certificate.t()) :: tuple()
  def public_key_algorithm(cert) do
    {:OTPCertificate,
      {:OTPTBSCertificate, _, _, _, _, _, _,
        {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, public_key_algorithm, _}, _},
        _,
        _,
        _},
      _,
      _
    } = cert

    public_key_algorithm
  end
end
