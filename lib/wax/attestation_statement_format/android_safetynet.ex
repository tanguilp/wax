defmodule Wax.AttestationStatementFormat.AndroidSafetynet do
  require Logger

  @behaviour Wax.AttestationStatementFormat

  @root_cert File.read!("lib/wax/attestation_statement_format/android_safetynet/GSR2.crt")

  @impl Wax.AttestationStatementFormat
  def verify(att_stmt, auth_data, client_data_hash) do
    try do
      [header_b64, payload_b64, _sig] = String.split(att_stmt["response"], ".")

      payload =
        payload_b64
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      header =
        header_b64
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()

      with :ok <- valid_cbor?(att_stmt),
           :ok <- valid_safetynet_response?(payload, att_stmt["ver"]),
           :ok <- nonce_valid?(auth_data.raw_bytes, client_data_hash, payload),
           :ok <- valid_cert_hostname?(header),
           :ok <- Wax.Utils.JWS.verify(att_stmt["response"], @root_cert)
      do
        leaf_cert =
          header["x5c"]
          |> List.first()
          |> Base.decode64!()

        {:ok, {:basic, leaf_cert}}
      else
        error ->
          error
      end
    rescue
      _ ->
        {:error, :attestation_safetynet_invalid_att_stmt}
    end
  end

  @spec valid_cbor?(Wax.Attestation.Statement.t()) :: :ok | {:error, any()}
  defp valid_cbor?(att_stmt) do
    if is_binary(att_stmt["ver"])
    and is_binary(att_stmt["response"])
    and length(Map.keys(att_stmt)) == 2 # only these two keys
    do
      :ok
    else
      {:error, :attestation_safetynet_invalid_cbor}
    end
  end

  @spec valid_safetynet_response?(map() | Keyword.t() | nil, String.t()) :: :ok | {:error, any()}

  defp valid_safetynet_response?(%{} = safetynet_response, _version) do
    #FIXME: currently unimplementable? see:
    # https://github.com/w3c/webauthn/issues/968
    # besides the spec seems to have an error with the `ctsProfileMatch` (`true` then `true`):
    # https://developer.android.com/training/safetynet/attestation#compat-check-response
    #
    # Therefore for now we just check `ctsProfileMatch`
    if safetynet_response["ctsProfileMatch"] == true do
      :ok
    else
      {:error, :attestation_safetynet_invalid_ctsProfileMatch}
    end
  end

  defp valid_safetynet_response?(_, _), do: {:error, :attestation_safetyney_invalid_payload}

  @spec nonce_valid?(Wax.AuthenticatorData.t(), binary(), map())
    :: :ok | {:error, any()}

  defp nonce_valid?(auth_data, client_data_hash, payload) do
    expected_nonce =
      Base.encode64(:crypto.hash(:sha256, auth_data.raw_bytes <> client_data_hash))

    if payload["nonce"] == expected_nonce do
      :ok
    else
      {:error, :attestation_safetynet_invalid_nonce}
    end
  end

  @spec valid_cert_hostname?(map()) :: :ok | {:error, any()}
  defp valid_cert_hostname?(header) do
    leaf_cert =
      header["x5c"]
      |> List.first()
      |> Base.decode64!()
      |> X509.Certificate.from_der!()

    #FIXME: verify it's indeed the SAN that must be checked
    # since spec says `hostname` (couldn't it be the CN?, both?)
    case X509.Certificate.extension(leaf_cert, :subject_alt_name) do
      {:Extension, {2, 5, 29, 17}, false, [dNSName: 'attest.android.com']} ->
        :ok

      _ ->
        {:error, :attestation_safetynet_invalid_hostname}
    end
  end
end
