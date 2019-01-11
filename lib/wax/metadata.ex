defmodule Wax.Metadata do
  require Logger
  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, %{})
  end

  def init(_state) do
    :ets.new(:wax_metadata, [:named_table, :set, :public])

    update_metadata()

    schedule_update()

    {:ok, []}
  end

  def handle_info(:update_metadata, _state) do
    update_metadata()

    schedule_update()

    {:noreply, []}
  end

  defp schedule_update() do
    Process.send_after(self(),
      :update_metadata,
      Application.get_env(:wax, :metadata_update_interval, 12 * 3600) * 1000)
  end

  def update_metadata() do
    Logger.info("Starting FIDO metadata update process")

    access_token =
      Application.get_env(:wax, :metadata_access_token)
      |> :erlang.binary_to_list()

    {:ok, {{_, 200, _}, _, body}} =
      :httpc.request('https://mds2.fidoalliance.org/?token=' ++ access_token)

    metadata = parse_jwt(:erlang.list_to_binary(body))

    Enum.each(
      metadata["entries"],
      fn entry ->
        Task.start(fn -> update_metadata_statement(entry) end)
      end
    )
  end

  @spec update_metadata_statement(map()) :: any()
  def update_metadata_statement(entry) do
    try do
      access_token =
        Application.get_env(:wax, :metadata_access_token)
        |> :erlang.binary_to_list()

      request = {
        :erlang.binary_to_list(entry["url"]) ++ '/?token=' ++ access_token,
        [{'accept', '*/*'}]
      }
      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, request, [], [])

      metadata_statement =
        body
        |> :erlang.list_to_binary()
        |> Base.url_decode64!()
        |> Jason.decode!()
        |> Wax.MetadataStatement.from_json()

      case metadata_statement do
        %Wax.MetadataStatement{aaguid: aaguid} when is_binary(aaguid) ->
          :ets.insert(:wax_metadata, {{:aaguid, aaguid}, metadata_statement})

        %Wax.MetadataStatement{aaid: aaid} when is_binary(aaid) ->
          :ets.insert(:wax_metadata, {{:aaid, aaid}, metadata_statement})

        _ ->
          Enum.each(
            metadata_statement.attestation_certificate_key_identifiers,
            fn acki ->
              :ets.insert(:wax_metadata, {{:acki, acki}, metadata_statement})
            end
          )
      end
    rescue
      e ->
        Logger.warn("Failed updating metadata aaid=#{entry["aaid"]}, reason: #{Exception.message(e)}")
    end
  end

  @spec parse_jwt(binary()) :: map()
  defp parse_jwt(binary) do
    [_header, body_b64, _sig] = String.split(binary, ".")

    body_b64
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
  end
end
