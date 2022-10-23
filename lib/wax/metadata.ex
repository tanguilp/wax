defmodule Wax.Metadata do
  require Logger
  use GenServer

  @moduledoc false

  @fido_alliance_root_cer_der """
                              -----BEGIN CERTIFICATE-----
                              MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
                              A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
                              Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
                              MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
                              A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
                              hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
                              RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
                              gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
                              KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
                              QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
                              XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
                              DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
                              LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
                              RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
                              jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
                              6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
                              mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
                              Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
                              WD9f
                              -----END CERTIFICATE-----
                              """
                              |> X509.Certificate.from_pem!()
                              |> X509.Certificate.to_der()

  @mdsv3_key {__MODULE__, :mdsv3_metadata}
  @local_key {__MODULE__, :local_metadata}

  @typedoc """
  A metadata statement

  For instance:

  ```
  %{
    "aaguid" => "2c0df832-92de-4be1-8412-88a8f074df4a",
    "attachmentHint" => ["external", "wireless", "nfc"],
    "attestationRootCertificates" => ["MIIB2DCCAX6gAwIBAgIQGBUrQbdDrm20FZnDsX2CBTAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQwMTAwMDAwMFoYDzIwNDgwMzMxMjM1OTU5WjBLMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsFYEEhiJuqqnMgQjSiivBjV7DGCTf4XBBH/B7uvZsKxXShF0L8uDISWUvcExixRs6gB3oldSrjox6L8T94NOzqNCMEAwHQYDVR0OBBYEFEu9hyYRrRyJzwRYvnDSCIxrFiO3MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIDHSb2mbNDAUNXvpPU0oWKeNye0fQ2l9D01AR2+sLZdhAiEAo3wz684IFMVsCCRmuJqxH6FQRESNqezuo1E+KkGxWuM=",
     "MIIBfjCCASWgAwIBAgIBATAKBggqhkjOPQQDAjAXMRUwEwYDVQQDDAxGVCBGSURPIDAyMDAwIBcNMTYwNTAxMDAwMDAwWhgPMjA1MDA1MDEwMDAwMDBaMBcxFTATBgNVBAMMDEZUIEZJRE8gMDIwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNBmrRqVOxztTJVN19vtdqcL7tKQeol2nnM2/yYgvksZnr50SKbVgIEkzHQVOu80LVEE3lVheO1HjggxAlT6o4WjYDBeMB0GA1UdDgQWBBRJFWQt1bvG3jM6XgmV/IcjNtO/CzAfBgNVHSMEGDAWgBRJFWQt1bvG3jM6XgmV/IcjNtO/CzAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiAwfPqgIWIUB+QBBaVGsdHy0s5RMxlkzpSX/zSyTZmUpQIgB2wJ6nZRM8oX/nA43Rh6SJovM2XwCCH//+LirBAbB0M=",
     "MIIB2DCCAX6gAwIBAgIQFZ97ws2JGPEoa5NI+p8z1jAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQwMTAwMDAwMFoYDzIwNDgwMzMxMjM1OTU5WjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnfAKbjvMX1Ey1b6k+WQQdNVMt9JgGWyJ3PvM4BSK5XqTfo++0oAj/4tnwyIL0HFBR9St+ktjqSXDfjiXAurs86NCMEAwHQYDVR0OBBYEFNGhmE2Bf8O5a/YHZ71QEv6QRfFUMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIQC3sT1lBjGeF+xKTpzV1KYU2ckahTd4mLJyzYOhaHv4igIgD2JYkfyH5Q4Bpo8rroO0It7oYjF2kgy/eSZ3U9Glaqw="],
    "attestationTypes" => ["basic_full"],
    "authenticationAlgorithms" => ["secp256r1_ecdsa_sha256_raw"],
    "authenticatorGetInfo" => %{
      "aaguid" => "2c0df83292de4be1841288a8f074df4a",
      "algorithms" => [%{"alg" => -7, "type" => "public-key"}],
      "extensions" => ["credProtect", "hmac-secret"],
      "maxCredentialCountInList" => 6,
      "maxCredentialIdLength" => 96,
      ...
    },
    "authenticatorVersion" => 1,
    "cryptoStrength" => 128,
    "description" => "Feitian FIDO Smart Card",
    "icon" => "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAAAUCAMAAAAtBkrlAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABHZpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMDE0IDc5LjE1Njc5NywgMjAxNC8wOC8yMC0wOTo1MzowMiAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25zLmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bXA6Q3JlYXRvclRvb2w9IkFkb2JlIFBob3Rvc2hvcCBDQyAyMDE0IChNYWNpbnRvc2gpIiB4bXA6Q3JlYXRlRGF0ZT0iMjAxNi0xMi0zMFQxNDozMzowOCswODowMCIgeG1wOk1vZGlmeURhdGU9IjIwMTYtMTItMzBUMDc6MzE6NTkrMDg6MDAiIHhtcDpNZXRhZGF0YURhdGU9IjIwMTYtMTItMzBUMDc6MzE6NTkrMDg6MDAiIGRjOmZvcm1hdD0iaW1hZ2UvcG5nIiBwaG90b3Nob3A6SGlzdG9yeT0iMjAxNi0xMi0zMFQxNTozMDoyNyswODowMCYjeDk75paH5Lu2IOacquagh+mimC0xIOW3suaJk+W8gCYjeEE7IiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjJFNzFCRkZDQzY3RjExRTY5NzhEQTlDQkI2NDYzRjkwIiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOjJFNzFCRkZEQzY3RjExRTY5NzhEQTlDQkI2NDYzRjkwIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6MkU3MUJGRkFDNjdGMTFFNjk3OERBOUNCQjY0NjNGOTAiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6MkU3MUJGRkJDNjdGMTFFNjk3OERBOUNCQjY0NjNGOTAiLz4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+IDw/eHBhY2tldCBlbmQ9InIiPz477JXFAAAAYFBMVEX///8EVqIXZavG2OoqcLG2zOOkwt0BSJtqlcXV4u+autlWhbzk7PUAMY9HcrKjtNbq8feAl8aBoszz9vpdjsGGqtF3n8uTsNSZpc6JsNT5+v0xYKnu8Pff5/L48fg/friczJgYAAADAElEQVR42kRUCZbDIAjFXZOY1TatNc39bzksSYc3r4ME4fMBAaD6zl8y/9TOget8d5jfN78bwM/dDCRpR521zXfojHJ05IIyhBAUSVAONdGzBYt2f7KFrfkJaAkHh9FZhcDXHRkTKo9MLihGaavImnV3qyEX0Eprgz/4DwUD7kCHRnd8QFN43Go4UVmDDgza4w27oizdA2+cK+uuUpjjo2+xwc/42W50x5LGYeDBsR0HVIx5x8iF60CblbTEEkFr27bNDBUVSq1OKVPbE62b3EH8FqBg5OOOEuc2t8ZJiqMOuGp+cKjg7wVGceozqN4pxgVPQkjFYgbVJKDUhDCjYrawP5q4ETgC9fIMRHtitpQcCvJOELcbMsQgnciRkljpyQjvG44jqBUETFiBi1PEIyekOzsW+Ty5cLHos5R+dMS1LtSSxf3gQHczR2CI4gMNpW4IRA1QMa6tJ4+C6uHuGE8mNDIyFqg/OP/MMUueS6Iq8S90dAeBJSEy/qKkK+BNwz8cYY4jb5J6u4iWCI2B1Z56LW5kEc4hkdMpsvUC5585SX0QubcgNqyfgDFEcTt+40/0S5Nx0waCw3OKkcObA5In0AYp01pjjw2n626UDjtHwa28iHuTKqtrv+reW41NZ6iGlr7uuLJCfkFtctcG04sgm1eNS+ZaDnpaTErGoyX5JK2iMz8xs0nOwWGcPDN49qaCd4bzJozDZm/aBK+EozLw+XhNBiYwHf0siOu1XPkG/zKwvqYKcfSwDEcH/oUe07es/WQ8rIyg2DOXj8tjkZduDB/b8hzDllMMOCS5BEnd534f8ti3UZc4kMs3xLyafMSsJhdG8XPqjNk5tAgO25feKChnVdDj/J0FMkOsU/xMBv0wFhYeEGfVH13fuDU0yDFLa4fc7RnWHBfuTFV2tEmNwadc7ac3UY2jfBl7HT36fe34iQO5mNCFFBW07KjPgqhOLU01vZ8PueZ2JClFZN8jkUs69uka9ePp6+EfL4AF5+NywSbirHtcB8Ml/gkwAEjkK64KjHPeAAAAAElFTkSuQmCC",
    "keyProtection" => [...],
    # ...
  }
  ```
  """
  @type statement :: map()

  defmodule MetadataStatementNotFound do
    defexception message: "Authenticator metadata was not found"
  end

  defmodule AuthenticatorStatusNotAcceptable do
    defexception [:status]

    @impl true
    def message(%{status: status}) do
      """
      Authenticator was not accepted. Its security might have been broken,
      or he's not sufficiently certified yet. Rejected status: #{status}
      """
    end
  end

  # client API

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @spec get_by_aaguid(binary(), Wax.Challenge.t()) :: {:ok, statement()} | {:error, Exception.t()}
  def get_by_aaguid(aaguid_bin, challenge) do
    ensure_loaded()

    <<
      a::binary-size(8),
      b::binary-size(4),
      c::binary-size(4),
      d::binary-size(4),
      e::binary-size(12)
    >> = Base.encode16(aaguid_bin, case: :lower)

    aaguid_str = a <> "-" <> b <> "-" <> c <> "-" <> d <> "-" <> e

    [:persistent_term.get(@mdsv3_key, []), :persistent_term.get(@local_key, [])]
    |> List.flatten()
    |> Enum.find(fn
      %{"aaguid" => ^aaguid_str} ->
        true

      _ ->
        false
    end)
    |> check_metadata_validity_and_return(challenge)
  end

  @spec get_by_acki(binary(), Wax.Challenge.t()) :: {:ok, statement()} | {:error, Exception.t()}
  def get_by_acki(acki_bin, challenge) do
    ensure_loaded()

    acki_str = Base.encode16(acki_bin, case: :lower)

    [:persistent_term.get(@mdsv3_key, []), :persistent_term.get(@local_key, [])]
    |> List.flatten()
    |> Enum.find(fn
      %{"attestationCertificateKeyIdentifiers" => ackis} ->
        acki_str in ackis

      _ ->
        false
    end)
    |> check_metadata_validity_and_return(challenge)
  end

  # from MDSv3
  defp check_metadata_validity_and_return(%{"statusReports" => _} = metadata, challenge) do
    if metadata["statusReports"]["status"] in challenge.acceptable_authenticator_statuses do
      {:ok, metadata["metadataStatement"]}
    else
      {:error, %AuthenticatorStatusNotAcceptable{status: metadata["statusReports"]["status"]}}
    end
  end

  # from local loaded file
  defp check_metadata_validity_and_return(%{} = metadata, _challenge) do
    {:ok, metadata}
  end

  defp check_metadata_validity_and_return(nil, _challenge) do
    {:error, %MetadataStatementNotFound{}}
  end

  defp ensure_loaded() do
    GenServer.call(__MODULE__, :ping, :infinity)
  end

  # server callbacks

  @impl true
  def init(_state) do
    {:ok, %{last_modified: nil, version_number: -1}, {:continue, :update_metadata}}
  end

  @impl true
  def handle_continue(:update_metadata, state) do
    load_from_dir()
    state = update_metadata(state)

    schedule_update()

    Process.send(self(), :update_from_file, [])

    {:noreply, state}
  end

  @impl true
  def handle_call(:ping, _from, state) do
    {:reply, :pong, state}
  end

  @impl true
  def handle_info(:update_metadata, state) do
    state = update_metadata(state)

    schedule_update()

    {:noreply, state}
  end

  def handle_info(_reason, state) do
    {:noreply, state}
  end

  defp schedule_update() do
    Process.send_after(
      self(),
      :update_metadata,
      Application.get_env(:wax_, :metadata_update_interval, 3600) * 1000
    )
  end

  defp update_metadata(state) do
    if Application.get_env(:wax_, :update_metadata) do
      do_update_metadata(state)
    else
      state
    end
  end

  defp do_update_metadata(state) do
    certs = :public_key.cacerts_get()

    ssl_opts = [
      cacerts: certs,
      verify: :verify_peer,
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ],
      crl_check: true,
      crl_cache: {:ssl_crl_cache, {:internal, [http: 1000]}}
    ]

    headers =
      if state[:last_modified] do
        [{'if-modified-since', state[:last_modified]}]
      else
        []
      end

    :httpc.request(:get, {"https://mds.fidoalliance.org", headers}, [ssl: ssl_opts], [])
    |> case do
      {:ok, {{_, 200, _}, headers, body}} ->
        version_number =
          body
          |> :erlang.list_to_binary()
          |> process_and_save_metadata(state)

        last_modified = List.keyfind(headers, "last-modified", 0)

        %{state | last_modified: last_modified, version_number: version_number}

      {:ok, {{_, 304, _}, _headers, _body}} ->
        state

      error ->
        Logger.info("#{__MODULE__}: failed to download MDSv3 metadata, error: #{inspect(error)}")

        state
    end
  end

  defp process_and_save_metadata(jws, state) do
    case Wax.Utils.JWS.verify_with_x5c(jws, @fido_alliance_root_cer_der) do
      {:ok, metadata} ->
        if metadata["no"] > state.version_number do
          :persistent_term.put(@mdsv3_key, metadata["entries"])
        end

        metadata["no"]

      {:error, reason} ->
        Logger.info("Failed to verify FIDO MDSV3 metadata (reason: #{inspect(reason)})")

        -1
    end
  end

  @doc """
  Forces reload of metadata statements from configured directory
  """
  @spec load_from_dir() :: [statement()]
  def load_from_dir() do
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

    statements = for file <- files, do: file |> File.read!() |> Jason.decode!()

    :persistent_term.put(@local_key, statements)

    statements
  end
end
