defmodule Wax.Utils.JWS do
  @moduledoc false

  require Record

  Record.defrecord(
    :ecdsa_signature,
    :"ECDSA-Sig-Value",
    Record.extract(:"ECDSA-Sig-Value", from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @spec verify(String.t(), binary()) :: :ok | {:error, any()}
  def verify(jws, root_cert_der) do
    try do
      [header_b64, payload_b64, sig_b64] = String.split(jws, ".")

      header =
        header_b64
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      cert_chain =
        header["x5c"]
        |> Enum.map(&Base.decode64!/1)
        |> Kernel.++([root_cert_der])

      case :public_key.pkix_path_validation(root_cert_der, Enum.reverse(cert_chain), []) do
        #FIXME: shall we check the CRL? Or are FIDO MDS sufficient?
        {:ok, _} ->
          public_key =
            cert_chain
            |> List.first()
            |> X509.Certificate.from_der!()
            |> X509.Certificate.public_key()

          digest_alg = digest_alg(header["alg"])

          message = header_b64 <> "." <> payload_b64

          File.write("testouille", message)

          sig = der_encoded_sig(sig_b64)

          if :public_key.verify(message, digest_alg, sig, public_key) do
            :ok
          else
            {:error, :jws_invalid_signature}
          end

        {:error, _} = error ->
          error
      end
    rescue
      _ ->
        {:error, :jws_decode_error}
    end
  end

  @spec der_encoded_sig(String.t()) :: binary()
  defp der_encoded_sig(sig_b64) do
    Base.url_decode64!(sig_b64, padding: false)
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
end
