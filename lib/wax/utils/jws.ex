defmodule Wax.Utils.JWS do
  @moduledoc false

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

      leaf_cert = List.first(cert_chain)

      case :public_key.pkix_path_validation(root_cert_der, Enum.reverse(cert_chain), []) do
        #FIXME: shall we check the CRL? Or are FIDO MDS sufficient?
        {:ok, _} ->
          public_key =
            leaf_cert
            |> X509.Certificate.from_der!()
            |> X509.Certificate.public_key()

          digest_alg = digest_alg(header["alg"])

          message = header_b64 <> "." <> payload_b64

          sig = Base.url_decode64!(sig_b64, padding: false)

          #FIXME: we don't check if the alg of the JWS header and the public key of
          # the certificate match (i.e. same algorithm) -> should we?

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

  @spec digest_alg(String.t()) :: :public_key.digest_type()
  defp digest_alg("RS256"), do: :sha256
  defp digest_alg("RS384"), do: :sha384
  defp digest_alg("RS512"), do: :sha512
  defp digest_alg("ES256"), do: :sha256
  defp digest_alg("ES384"), do: :sha384
  defp digest_alg("ES512"), do: :sha512
  defp digest_alg(_), do: raise "jws unsupported digest alg"
end
