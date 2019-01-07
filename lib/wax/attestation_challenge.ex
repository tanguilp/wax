defmodule Wax.AttestationChallenge do
  @enforce_keys [:bytes, :user]

  defstruct [
    :bytes,
    :user,
    :origin,
    :exp,
    :token_binding_status
  ]

  @type t :: %__MODULE__{
    bytes: binary(),
    user: Wax.User.t(),
    origin: String.t() | nil,
    exp: non_neg_integer() | nil,
    token_binding_status: any()
  }

  @spec new(Wax.User.t()) :: t()
  def new(user) do
    %__MODULE__{
      bytes: random_bytes(),
      user: user
    }
  end

  @spec random_bytes() :: binary
  def random_bytes() do
    :crypto.strong_rand_bytes(32)
  end
end
