defmodule Wax.ClientData do
  defmodule TokenBinding do
    @enforce_keys [:status]

    defstruct [
      :status,
      :id
    ]

    @type t :: %__MODULE__{
            status: String.t(),
            id: String.t()
          }
  end

  @enforce_keys [:type, :challenge, :origin]

  defstruct [
    :type,
    :challenge,
    :origin,
    :token_binding
  ]

  @type t :: %__MODULE__{
          type: :create | :get,
          challenge: binary(),
          origin: String.t(),
          token_binding: TokenBinding.t()
        }

  @type hash :: binary()

  @typedoc """
  The raw string as returned by the javascript WebAuthn API

  Example: `{"challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaY","clientExtensions":{},"hashAlgorithm":"SHA-256","origin":"http://localhost:4000","type":"webauthn.create"}`
  """

  @type raw_string :: String.t()

  @doc false

  @spec parse_raw_json(raw_string()) :: {:ok, t()} | {:error, Exception.t()}
  def parse_raw_json(client_data_json_raw) do
    with {:ok, client_data_map} <- decode_json_object(client_data_json_raw),
         {:ok, maybe_token_binding} <- parse_token_binding(client_data_map["tokenBinding"]),
         {:ok, type} <- parse_type(client_data_map["type"]),
         {:ok, challenge} <- parse_challenge(client_data_map["challenge"]),
         {:ok, origin} <- parse_origin(client_data_map["origin"]) do
      {:ok,
       %__MODULE__{
         type: type,
         challenge: challenge,
         origin: origin,
         token_binding: maybe_token_binding
       }}
    end
  end

  # The client data is sent by the browser and is therefore untrusted: any JSON value can
  # show up here, not only an object with the expected members
  defp decode_json_object(client_data_json_raw) do
    case Jason.decode(client_data_json_raw) do
      {:ok, %{} = client_data_map} ->
        {:ok, client_data_map}

      _ ->
        {:error, %Wax.InvalidClientDataError{reason: :malformed_json}}
    end
  end

  defp parse_type("webauthn.create"), do: {:ok, :create}
  defp parse_type("webauthn.get"), do: {:ok, :get}
  defp parse_type(_), do: {:error, %Wax.InvalidClientDataError{reason: :invalid_type}}

  defp parse_challenge(challenge) when is_binary(challenge) do
    case Base.url_decode64(challenge, padding: false) do
      {:ok, challenge} ->
        {:ok, challenge}

      :error ->
        {:error, %Wax.InvalidClientDataError{reason: :invalid_challenge}}
    end
  end

  defp parse_challenge(_) do
    {:error, %Wax.InvalidClientDataError{reason: :invalid_challenge}}
  end

  defp parse_origin(origin) when is_binary(origin), do: {:ok, origin}
  defp parse_origin(_), do: {:error, %Wax.InvalidClientDataError{reason: :invalid_origin}}

  defp parse_token_binding(nil) do
    {:ok, nil}
  end

  defp parse_token_binding(%{"status" => status} = token_binding)
       when status in ["supported", "not-supported"] do
    {:ok, %TokenBinding{status: status, id: token_binding["id"]}}
  end

  defp parse_token_binding(%{"status" => "present", "id" => id}) do
    {:ok, %TokenBinding{status: "present", id: id}}
  end

  defp parse_token_binding(_) do
    {:error, %Wax.InvalidClientDataError{reason: :invalid_token_binding_data}}
  end
end
