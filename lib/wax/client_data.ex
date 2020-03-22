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

  @spec parse_raw_json(raw_string()) :: {:ok, t()} | {:error, any()}

  def parse_raw_json(client_data_json_raw) do
    with {:ok, client_data_map} <- Jason.decode(client_data_json_raw),
         {:ok, maybe_token_binding} <- parse_token_binding(client_data_map["tokenBinding"])
    do
      type =
        case client_data_map["type"] do
          "webauthn.create" ->
            :create

          "webauthn.get" ->
            :get
        end

      {:ok, %__MODULE__{
        type: type,
        challenge: Base.url_decode64!(client_data_map["challenge"], padding: false),
        origin: client_data_map["origin"],
        token_binding: maybe_token_binding
        }}
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :client_data_json_parse_error}

      error ->
        error
    end
  end

  @spec parse_token_binding(any()) :: {:ok, TokenBinding.t() | nil} | {:error, atom()}
  defp parse_token_binding(nil) do
    {:ok, nil}
  end

  defp parse_token_binding(
    %{"status" => status} = token_binding)when status in ["supported", "not-supported"]
  do
    {:ok, %TokenBinding{status: status, id: token_binding["id"]}}
  end

  defp parse_token_binding(%{"status" => "present", "id" => id}) do
    {:ok, %TokenBinding{status: "present", id: id}}
  end

  defp parse_token_binding(_) do
    {:error, :client_data_invalid_token_binding_data}
  end
end
