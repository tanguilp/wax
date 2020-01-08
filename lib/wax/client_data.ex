defmodule Wax.ClientData do
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
    token_binding: any()
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
    with {:ok, client_data_map} <- Jason.decode(client_data_json_raw)
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
        token_binding: nil # unsupported
        }}
    else
      {:error, error} ->
        {:error, error}
    end
  end
end
