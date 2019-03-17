defmodule Wax.Metadata do
  require Logger
  use GenServer

  @moduledoc false

  @fido_alliance_root_cer_pem """
    -----BEGIN CERTIFICATE-----
    MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG
    A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk
    YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX
    DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs
    aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS
    b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+
    AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims
    rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw
    DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw
    HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw
    ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW
    DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU
    YjdBz56jSA==
    -----END CERTIFICATE-----
    """

  @fido_alliance_root_cer_der\
    @fido_alliance_root_cer_pem
    |> X509.Certificate.from_pem!()
    |> X509.Certificate.to_der()

  @table :wax_metadata
  @table_2 :wax_metadata_2

  # client API

  def start_link do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @spec get_by_aaguid(binary()) :: Wax.MetadataStatement.t() | nil

  def get_by_aaguid(aaguid_bin) do
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

    GenServer.call(__MODULE__, {:get, {:aaguid, aaguid_str}})
  end

  @spec get_by_acki(binary()) :: Wax.MetadataStatement.t() | nil

  def get_by_acki(acki_bin) do
    acki_str = Base.encode16(acki_bin, case: :lower)

    GenServer.call(__MODULE__, {:get, {:acki, acki_str}})
  end

  # server callbacks

  @impl true
  def init(_state) do
    :ets.new(@table, [:named_table, :set, :protected, {:read_concurrency, true}])
    :ets.new(@table_2, [:named_table, :set, :protected, {:read_concurrency, true}])

    {:ok, [serial_number: 0, serial_number_2: 0], {:continue, :update_metadata}}
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

    serial_number_2 =
      case update_metadata_2(state[:serial_number_2]) do
        new_serial_number_2 when is_integer(new_serial_number_2) ->
          new_serial_number_2

        _ ->
          state[:serial_number_2]
      end

    schedule_update()

    {:noreply, [serial_number: serial_number, serial_number_2: serial_number_2]}
  end

  @impl true
  def handle_call({:get, {type, value}}, _from, state) do
    case :ets.lookup(@table, {type, value}) do
      [{_, metadata_statement}] ->
        {:reply, metadata_statement, state}

      _ ->
        case :ets.lookup(@table_2, {type, value}) do
          [{_, metadata_statement}] ->
            {:reply, metadata_statement, state}

          _ ->
            {:reply, nil, state}
        end
    end
  end

  @impl true
  def handle_info(:update_metadata, state) do
    serial_number =
      case update_metadata(state[:serial_number]) do
        new_serial_number when is_integer(new_serial_number) ->
          new_serial_number

        _ ->
          state[:serial_number]
      end

    serial_number_2 =
      case update_metadata_2(state[:serial_number_2]) do
        new_serial_number_2 when is_integer(new_serial_number_2) ->
          new_serial_number_2

        _ ->
          state[:serial_number_2]
      end

    schedule_update()

    {:noreply, [serial_number: serial_number, serial_number_2: serial_number_2]}
  end

  defp schedule_update() do
    Process.send_after(self(),
      :update_metadata,
      Application.get_env(:wax, :metadata_update_interval, 12 * 3600) * 1000)
  end

  def update_metadata(serial_number) do
    #FIXME: handle
    #   verify sig
    #   revoked certs & other revocation mecanisms
    Logger.info("Starting FIDO metadata (1) update process")

    case HTTPoison.get("https://mds.fidoalliance.org") do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        process_metadata_toc(body, serial_number, @table)

      e ->
        Logger.warn("Unable to download metadata (#{inspect(e)})")
    end
  end

  def update_metadata_2(serial_number) do
    #FIXME: handle
    #   verify sig
    #   revoked certs & other revocation mecanisms
    Logger.info("Starting FIDO metadata (2) update process")

    access_token = Application.get_env(:wax, :metadata_access_token)

    if access_token do
      case HTTPoison.get("https://mds2.fidoalliance.org/?token=" <> access_token) do
        {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
          process_metadata_toc(body, serial_number, @table_2)

        e ->
          Logger.warn("Unable to download metadata (#{inspect(e)})")
      end
    else
      Logger.warn("No access token configured for FIDO metadata, metadata not updated. " <>
        "Some attestation formats and types won't be supported")

      :not_updated
    end
  end

  @spec process_metadata_toc(String.t(), non_neg_integer(), atom()) :: non_neg_integer() | :not_updated

  defp process_metadata_toc(jws, serial_number, table) do
    case Wax.Utils.JWS.verify(jws, @fido_alliance_root_cer_der) do
      _ ->
      #:ok ->
      # FIXME: JWS doesn't work for this specific JWT
        {%{"alg" => alg}, metadata} = parse_jwt(jws)

        if metadata["no"] > serial_number do
          # one of sha256, sha512, etc
          digest_alg = digest_from_jws_alg(alg)

          tasks = Enum.map(
            metadata["entries"],
            fn entry ->
              Task.async(fn -> update_metadata_statement(entry, digest_alg) end)
            end
          )

          # cleaning it first to avoid having to deal with diffing
          # since this GenServer call is blocking, no concurrent access
          # to the empty table can be made
          :ets.delete_all_objects(table)

          Enum.each(
            tasks,
            fn task ->
              metadata_statement = Task.await(task)

              case metadata_statement do
                %Wax.MetadataStatement{aaguid: aaguid} when is_binary(aaguid) ->
                  Logger.debug("Saving metadata for aaguid `#{aaguid}` " <>
                    "(#{metadata_statement.description})")

                  :ets.insert(table, {{:aaguid, aaguid}, metadata_statement})

                %Wax.MetadataStatement{aaid: aaid} when is_binary(aaid) ->
                  Logger.debug("Saving metadata for aaid `#{aaid}` " <>
                    "(#{metadata_statement.description})")

                  :ets.insert(table, {{:aaid, aaid}, metadata_statement})

                %Wax.MetadataStatement{attestation_certificate_key_identifiers: acki_list} ->
                  Enum.each(
                    acki_list,
                    fn acki ->
                      Logger.debug("Saving metadata for attestation certificate key identifier " <>
                        "`#{acki}` (#{metadata_statement.description})")

                      :ets.insert(table, {{:acki, acki}, metadata_statement})
                    end
                  )

                _ ->
                  :ok
              end
            end
          )

          metadata["no"]
        else
          Logger.info("Metadata not updated (`no` has not changed)")

          :not_updated
        end

      #{:error, reason} ->
        #Logger.warn("Invalid TOC metadata JWS signature, metadata not updated #{inspect(reason)}")
    end
  end

  @spec update_metadata_statement(map(), atom())
    :: any()
  def update_metadata_statement(entry, digest_alg) do
    access_token = Application.get_env(:wax, :metadata_access_token)

    url = if access_token do
      entry["url"] <> "?token=" <> access_token
    else
      entry["url"]
    end

    case HTTPoison.get(
      url,
      [],
      follow_redirect: true) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        if :crypto.hash(digest_alg, body) == Base.url_decode64!(entry["hash"]) do
          body
          |> Base.url_decode64!()
          |> Jason.decode!()
          |> Wax.MetadataStatement.from_json()
        else
          Logger.warn("Invalid hash for metadata entry at " <> entry["url"])
        end

      _ ->
        Logger.warn("Failed to download metadata statement at " <> entry["url"])
    end
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
end
