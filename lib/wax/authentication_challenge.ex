defmodule Wax.AuthenticationChallenge do
  @enforce_keys [:bytes, :user]

  defstruct [
    :bytes,
    :user,
    :allow_credentials,
    :origin,
    :exp,
    :token_binding_status
  ]

  @type t :: %__MODULE__{
    bytes: binary(),
    user: Wax.User.t(),
    allow_credentials: [any()],
    origin: String.t() | nil,
    exp: non_neg_integer() | nil,
    token_binding_status: any()
  }

  @spec new(Wax.user_id()) :: t()
  def new(user) do
    %__MODULE__{
      bytes: random_bytes(),
      user: user,
      allow_credentials: Enum.map(:ets.lookup(:wax_credential_store, user),
                                  fn {_, cred_id, _} -> cred_id end)
    }
  end

  @spec random_bytes() :: binary
  def random_bytes() do
    :crypto.strong_rand_bytes(32)
  end
end
