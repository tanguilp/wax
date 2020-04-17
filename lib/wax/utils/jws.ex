defmodule Wax.Utils.JWS do
  @moduledoc false

  require Record

  Record.defrecord(
    :ecdsa_signature,
    :"ECDSA-Sig-Value",
    Record.extract(:"ECDSA-Sig-Value", from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @spec verify_with_x5c(String.t(), binary(), [String.t()]) :: :ok | {:error, any()}
  def verify_with_x5c(jws, root_cert_der, crl_uris \\ []) do
    [header_b64, payload_b64, sig_b64] = String.split(jws, ".")

    header =
      header_b64
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()

    cert_chain =
      header["x5c"]
      |> Enum.map(&Base.decode64!/1)
      |> Kernel.++([root_cert_der])

    public_key =
      cert_chain
      |> List.first()
      |> X509.Certificate.from_der!()
      |> X509.Certificate.public_key()

    digest_alg = digest_alg(header["alg"])

    message = header_b64 <> "." <> payload_b64

    sig =
      sig_b64
      |> Base.url_decode64!(padding: false)
      |> maybe_encoded_sig(header["alg"])

    with {:ok, _} <- :public_key.pkix_path_validation(root_cert_der, Enum.reverse(cert_chain), []),
         true <- :public_key.verify(message, digest_alg, sig, public_key),
         :ok <- crl_validation(cert_chain, crl_uris)
    do
      :ok
    else
      {:error, {:bad_cert, _}} ->
        {:error, :jws_path_validation_bad_cert}

      false ->
        {:error, :jws_invalid_signature}

      {:error, _} = error ->
        error
    end
  rescue
    _e ->
      {:error, :jws_decode_error}
  end

  @spec maybe_encoded_sig(binary(), String.t()) :: binary()
  defp maybe_encoded_sig(sig, alg) when alg in ["ES256", "ES384", "ES512"] do
    der_encoded_sig(sig)
  end

  defp maybe_encoded_sig(sig, _alg) do
    sig
  end

  @spec der_encoded_sig(binary()) :: binary()
  defp der_encoded_sig(sig) do
    sig
    |> new_der_encoded_sig()
    |> to_der_sig()
  end

  defp new_der_encoded_sig(r, s) when is_integer(r) and is_integer(s) do
    ecdsa_signature(r: r, s: s)
  end

  defp new_der_encoded_sig(raw) when is_binary(raw) do
    size = raw |> byte_size() |> div(2)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>> = raw
    new_der_encoded_sig(r, s)
  end

  # Export to DER binary format, for use with :public_key.verify/4
  defp to_der_sig(ecdsa_signature() = signature) do
    :public_key.der_encode(:"ECDSA-Sig-Value", signature)
  end

  @spec digest_alg(String.t()) :: :public_key.digest_type()
  defp digest_alg("RS256"), do: :sha256
  defp digest_alg("RS384"), do: :sha384
  defp digest_alg("RS512"), do: :sha512
  defp digest_alg("ES256"), do: :sha256
  defp digest_alg("ES384"), do: :sha384
  defp digest_alg("ES512"), do: :sha512
  defp digest_alg(_), do: raise "jws unsupported digest alg"

  @spec crl_validation([binary()], [String.t()]) :: :ok | {:error, atom()}
  defp crl_validation(cert_chain, crl_uris) do
    with {:ok, crls} <- get_crls(crl_uris)
    do
      revoked_certs_serial_numbers = revoked_certs_serial_numbers(crls)

      Enum.all?(
        cert_chain,
        fn crt ->
          crt_serial_number =
            crt
            |> X509.Certificate.from_der!()
            |> Wax.Utils.Certificate.serial_number()
          crt_serial_number not in revoked_certs_serial_numbers
        end
      )
      |> if do
        :ok
      else
        {:jws_crl_revoked_certificate}
      end
    end
  end

  defp get_crls(crl_uris) do
    crls =
      for crl_uri <- crl_uris do
        crl_uri
        |> HTTPoison.get!()
        |> Map.get(:body)
        |> X509.CRL.from_pem!()
      end

    {:ok, crls}
  rescue
    _e ->
      {:error, :jws_crl_retrieval_error}
  end

  defp revoked_certs_serial_numbers(crls) do
    for crl <- crls do
      {:CertificateList,
        {:TBSCertList,
          _version,
          _signature,
          _issuer,
          _this_update,
          _next_update,
          revoked_certificates,
          _crl_extensions},
        _sig_alg,
        _sig} = crl

      case revoked_certificates do
        :asn1_NOVALUE ->
          []

        _ ->
          for revoked_certificate <- revoked_certificates do
            {
              :TBSCertList_revokedCertificates_SEQOF,
              user_certificate,
              _revocation_date,
              _crl_entry_extensions
            } = revoked_certificate

            user_certificate
          end
      end
    end
    |> List.flatten()
  end
end
