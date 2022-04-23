defmodule Wax.Metadata do
  require Logger
  use GenServer

  @moduledoc false

  @fido_alliance_root_cer_der \
    """
    -----BEGIN CERTIFICATE-----
    MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4
    GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbF
    NpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwM
    zE4MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzET
    MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQY
    JKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2Ec
    WtiHL8RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUh
    hB5uzsTgHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL
    0gRgykmmKPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65
    TpjoWc4zdQQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rU
    AVSNECMWEZXriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCA
    wEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
    BBYEFI/wS3+oLkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNv
    AUKr+yAzv95ZURUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8
    dEe3jgr25sbwMpjjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw
    8lo/s7awlOqzJCK6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0
    095MJ6RMG3NzdvQXmcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVE
    TI53O9zJrlAGomecsMx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02
    JQZR7rkpeDMdmztcpHWD9f
    -----END CERTIFICATE-----
    """
    |> X509.Certificate.from_pem!()
    |> X509.Certificate.to_der()

  @table :wax_metadata

  @crl_uris ["http://crl.globalsign.com/root-r3.crl"]

  # client API

  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @spec get_by_aaguid(binary(), Wax.Challenge.t()) :: Wax.Metadata.Statement.t() | nil

  def get_by_aaguid(
    aaguid_bin,
    %Wax.Challenge{acceptable_authenticator_statuses: acceptable_authenticator_statuses}
  ) do
    # it is needed to convert binary aaguid (16 bytes) to its string representation as
    # used in the metadata service, such as `77010bd7-212a-4fc9-b236-d2ca5e9d4084`
    <<
      a::binary-size(8),
      b::binary-size(4),
      c::binary-size(4),
      d::binary-size(4),
      e::binary-size(12)
    >> = Base.encode16(aaguid_bin, case: :lower)

    aaguid_str = a <> "-" <> b <> "-" <> c <> "-" <> d <> "-" <> e

    case GenServer.call(__MODULE__, {:get, {:aaguid, aaguid_str}}) do
      {nil, metadata_statement} ->
        metadata_statement

      {toc_entry, metadata_statement} ->
        if authenticator_status_allowed?(toc_entry, acceptable_authenticator_statuses) do
          metadata_statement
        else
          Logger.warn(
            "Authenticator `#{metadata_statement}` was not used because its status is " <>
            "not whitelisted (TOC entry: `#{toc_entry}`)"
          )

          nil
        end

      _ ->
        nil
    end
  end

  @spec get_by_acki(binary(), Wax.Challenge.t()) :: Wax.Metadata.Statement.t() | nil

  def get_by_acki(
    acki_bin,
    %Wax.Challenge{acceptable_authenticator_statuses: acceptable_authenticator_statuses}
  ) do
    acki_str = Base.encode16(acki_bin, case: :lower)

    case GenServer.call(__MODULE__, {:get, {:acki, acki_str}}) do
      {nil, metadata_statement} ->
        metadata_statement

      {toc_entry, metadata_statement} ->
        if authenticator_status_allowed?(toc_entry, acceptable_authenticator_statuses) do
          metadata_statement
        else
          Logger.warn(
            "Authenticator `#{metadata_statement}` was not used because its status is " <>
            "not whitelisted (TOC entry: `#{toc_entry}`)"
          )

          nil
        end

      nil ->
        nil
    end
  end

  @spec authenticator_status_allowed?(map(), [Wax.Metadata.TOCEntry.StatusReport.status()]) ::
    bool()
  defp authenticator_status_allowed?(
    %{status_reports: status_reports},
    acceptable_authenticator_statuses
  ) do
    latest_report = List.last(status_reports)

    latest_report.status in acceptable_authenticator_statuses
  end

  # server callbacks

  @impl true
  def init(_state) do
    :ets.new(@table, [:named_table, :set, :protected, {:read_concurrency, true}])

    {:ok, [serial_number: 0], {:continue, :update_metadata}}
  end

  @impl true
  def handle_continue(:update_metadata, state) do
    serial_number =
      case update_metadata(state[:serial_number]) do
        new_serial_number when is_integer(new_serial_number) ->
          new_serial_number

        _ ->
          state[:serial_number]
      end

    schedule_update()

    Process.send(self(), :update_from_file, [])

    {:noreply, [serial_number: serial_number]}
  end

  @impl true
  def handle_call({:get, {type, value}}, _from, state) do
    case :ets.lookup(@table, {type, value}) do
      [{_, toc_payload_entry, metadata_statement, _source}] ->
        {:reply, {toc_payload_entry, metadata_statement}, state}

      _ ->
        {:reply, nil, state}
    end
  end

  def handle_call(_, _, state), do: {:noreply, state}

  @impl true
  def handle_cast(_, state), do: {:noreply, state}

  @impl true
  def handle_info(:update_metadata, state) do
    serial_number =
      case update_metadata(state[:serial_number]) do
        new_serial_number when is_integer(new_serial_number) ->
          new_serial_number

        _ ->
          state[:serial_number]
      end

    schedule_update()

    {:noreply, [serial_number: serial_number]}
  end

  def handle_info(:update_from_file, state) do
    load_from_dir()

    {:noreply, state}
  end

  def handle_info(reason, state) do
    Logger.debug("#{__MODULE__}: received handle_info/2 message: #{inspect(reason)}")
    {:noreply, state}
  end

  defp schedule_update() do
    Process.send_after(self(),
      :update_metadata,
      Application.get_env(:wax_, :metadata_update_interval, 12 * 3600) * 1000)
  end

  def update_metadata(serial_number) do
    Logger.info("Starting FIDO metadata update process")

    case http_get("https://mds.fidoalliance.org/") do
      {:ok, jws_toc} ->
        process_metadata_toc(jws_toc, serial_number)

      {:error, reason} ->
        Logger.warn("Unable to download metadata (#{inspect(reason)})")

        :not_updated
    end
  end

  @spec process_metadata_toc(String.t(), non_neg_integer()) :: non_neg_integer() | :not_updated

  defp process_metadata_toc(jws, serial_number) do
    case Wax.Utils.JWS.verify_with_x5c(jws, @fido_alliance_root_cer_der, @crl_uris) do
      :ok ->
        {_, metadata} = parse_jwt(jws)

        if metadata["no"] > serial_number do
          toc_payload_entry = Enum.map(metadata["entries"], &build_toc_payload_entry/1)
          metadata_statements = Enum.map(metadata["entries"], &build_metadata_statement_entry/1)

          :ets.match_delete(:wax_metadata, {:_, :_, :_, :MDSv2})

          Enum.each(
            Enum.zip(toc_payload_entry, metadata_statements),
            fn {toc_entry, {:ok, metadata_statement}} ->
              case metadata_statement do
                %Wax.Metadata.Statement{} ->
                  save_metadata_statement(metadata_statement, :MDSv2, toc_entry)

                _ ->
                  Logger.error("Failed to load data for TOC entry `#{inspect(toc_entry)}`")

                  :ok
              end
            end
          )

          metadata["no"]
        else
          Logger.info("Metadata not updated (`no` has not changed)")

          :not_updated
        end

      {:error, reason} ->
        Logger.warn(
          "Invalid TOC metadata JWS signature, metadata not updated #{inspect(reason)}")
    end
  rescue
    _e ->
      {:error, :crl_retrieval_failed}
  end

  @spec parse_jwt(binary()) :: {map(), map()}
  defp parse_jwt(binary) do
    [header_b64, body_b64, _sig] = String.split(binary, ".")

    {
      header_b64
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!(),
      body_b64
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!(),
    }
  end

  @spec build_toc_payload_entry(map()) :: Wax.Metadata.TOCEntry.t()
  defp build_toc_payload_entry(entry) do
    %Wax.Metadata.TOCEntry{
      aaid: entry["aaid"],
      aaguid: entry["aaguid"],
      attestation_certificate_key_identifiers: entry["attestationCertificateKeyIdentifiers"],
      hash: entry["hash"],
      url: entry["url"],
      biometric_status_reports:
        Enum.map(entry["biometricStatusReports"] || [], &build_biometric_status_report/1),
      status_reports: Enum.map(entry["statusReports"], &build_status_report/1),
      time_of_last_status_change:
        if entry["timeOfLastStatusChange"] do
          Date.from_iso8601!(entry["timeOfLastStatusChange"])
        end,
      rogue_list_url: entry["rogueListURL"],
      rogue_list_hash: entry["rogueListHash"]
    }
  end

  @spec build_metadata_statement_entry(map()) :: Wax.Metadata.Statement.t()
  defp build_metadata_statement_entry(%{"metadataStatement" => metadata_statement}) do
    {:ok, statement} = Wax.Metadata.Statement.from_json(metadata_statement)
    statement
  end

  @spec build_biometric_status_report(map()) :: Wax.Metadata.TOCEntry.BiometricStatusReport.t()
  defp build_biometric_status_report(status) do
    %Wax.Metadata.TOCEntry.BiometricStatusReport{
      cert_level: status["certLevel"],
      modality: status["modality"],
      effective_date:
        if status["effectiveDate"] do
          Date.from_iso8601!(status["effectiveDate"])
        end,
      certification_descriptor: status["certificationDescriptor"],
      certificate_number: status["certificateNumber"],
      certification_policy_version: status["certificationPolicyVersion"],
      certification_requirements_version: status["certificationRequirementsVersion"]
    }
  end

  @spec build_status_report(map()) :: Wax.Metadata.TOCEntry.StatusReport.t()
  defp build_status_report(status) do
    %Wax.Metadata.TOCEntry.StatusReport{
      status: authenticator_status(status["status"]),
      effective_date:
        if status["effectiveDate"] do
          Date.from_iso8601!(status["effectiveDate"])
        end,
      certificate: status["certificate"],
      url: status["url"],
      certification_descriptor: status["certificationDescriptor"],
      certificate_number: status["certificateNumber"],
      certification_policy_version: status["certificationPolicyVersion"],
      certification_requirements_version: status["certificationRequirementsVersion"]
    }
  end

  @spec authenticator_status(String.t()) :: Wax.Metadata.TOCEntry.StatusReport.status()
  defp authenticator_status("NOT_FIDO_CERTIFIED"), do: :not_fido_certified
  defp authenticator_status("FIDO_CERTIFIED"), do: :fido_certified
  defp authenticator_status("USER_VERIFICATION_BYPASS"), do: :user_verification_bypass
  defp authenticator_status("ATTESTATION_KEY_COMPROMISE"), do: :attestation_key_compromise
  defp authenticator_status("USER_KEY_REMOTE_COMPROMISE"), do: :user_key_remote_compromise
  defp authenticator_status("USER_KEY_PHYSICAL_COMPROMISE"), do: :user_key_physical_compromise
  defp authenticator_status("UPDATE_AVAILABLE"), do: :update_available
  defp authenticator_status("REVOKED"), do: :revoked
  defp authenticator_status("SELF_ASSERTION_SUBMITTED"), do: :self_assertion_submitted
  defp authenticator_status("FIDO_CERTIFIED_L1"), do: :fido_certified_l1
  defp authenticator_status("FIDO_CERTIFIED_L1plus"), do: :fido_certified_l1plus
  defp authenticator_status("FIDO_CERTIFIED_L2"), do: :fido_certified_l2
  defp authenticator_status("FIDO_CERTIFIED_L2plus"), do: :fido_certified_l2plus
  defp authenticator_status("FIDO_CERTIFIED_L3"), do: :fido_certified_l3
  defp authenticator_status("FIDO_CERTIFIED_L3plus"), do: :fido_certified_l3plus

  #see section 3.1 of https://www.rfc-editor.org/rfc/rfc7518.txt
  @spec digest_from_jws_alg(String.t()) :: atom()
  defp digest_from_jws_alg("HS256"), do: :sha256
  defp digest_from_jws_alg("HS384"), do: :sha384
  defp digest_from_jws_alg("HS512"), do: :sha512
  defp digest_from_jws_alg("RS256"), do: :sha256
  defp digest_from_jws_alg("RS384"), do: :sha384
  defp digest_from_jws_alg("RS512"), do: :sha512
  defp digest_from_jws_alg("ES256"), do: :sha256
  defp digest_from_jws_alg("ES384"), do: :sha384
  defp digest_from_jws_alg("ES512"), do: :sha512
  defp digest_from_jws_alg("PS256"), do: :sha256
  defp digest_from_jws_alg("PS384"), do: :sha384
  defp digest_from_jws_alg("PS512"), do: :sha512

  @spec load_from_dir() :: any()
  defp load_from_dir() do
    :ets.match_delete(:wax_metadata, {:_, :_, :_, :file})

    files =
      case Application.get_env(:wax_, :metadata_dir, nil) do
        nil ->
          []

        app when is_atom(app) ->
          app
          |> :code.priv_dir()
          |> List.to_string()
          |> Kernel.<>("/fido2_metadata/*")
          |> Path.wildcard()

        path when is_binary(path) ->
          Path.wildcard(path <> "/*")
      end

    Enum.each(
      files,
      fn file_path ->
        with {:ok, file_content} <- File.read(file_path),
             {:ok, parsed_json} <- Jason.decode(file_content),
             {:ok, metadata_statement} <- Wax.Metadata.Statement.from_json(parsed_json)
        do
          save_metadata_statement(metadata_statement, :file, nil)
        else
          {:error, reason} ->
            Logger.warn(
              "Failed to load metadata statement from `#{file_path}` (reason: #{inspect(reason)})"
            )
        end
      end
    )
  end

  @spec save_metadata_statement(
    Wax.Metadata.Statement.t(),
    source :: atom(),
    Wax.Metadata.TOCEntry.t() | nil
  ) :: any()
  defp save_metadata_statement(metadata_statement, source, maybe_toc_entry) do
    desc = metadata_statement.description

    case metadata_statement do
      %Wax.Metadata.Statement{aaguid: aaguid} when is_binary(aaguid) ->
        Logger.debug("Saving metadata for aaguid `#{aaguid}` (#{desc})")

        :ets.insert(
          :wax_metadata,
          {{:aaguid, aaguid}, maybe_toc_entry, metadata_statement, source}
        )

      %Wax.Metadata.Statement{aaid: aaid} when is_binary(aaid) ->
        Logger.debug("Saving metadata for aaid `#{aaid}` (#{desc})")

        :ets.insert(
          :wax_metadata,
          {{:aaguid, aaid}, maybe_toc_entry, metadata_statement, source}
        )

      %Wax.Metadata.Statement{attestation_certificate_key_identifiers: acki_list} ->
        Enum.each(
          acki_list,
          fn acki ->
            Logger.debug(
              "Saving metadata for attestation certificate key identifier `#{acki}` (#{desc})"
            )

            :ets.insert(
              :wax_metadata,
              {{:acki, acki}, maybe_toc_entry, metadata_statement, source}
            )
          end
        )
    end
  end

  defp http_get(url) do
    client =
      Application.get_env(:wax_, :tesla_middlewares, [])
      |> Kernel.++([Tesla.Middleware.FollowRedirects])
      |> Tesla.client()

    case Tesla.get(client, url) do
      {:ok, %Tesla.Env{status: status, body: body}} when status in 200..299 ->
        {:ok, body}

      {:ok, %Tesla.Env{status: status}} ->
        {:error, "MDSv2 responded with HTTP error #{status}"}

      {:error, _} = error ->
        error
    end
  end
end
