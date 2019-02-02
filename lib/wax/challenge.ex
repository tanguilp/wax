defmodule Wax.Challenge do
  @enforce_keys [:bytes, :user, :origin, :rp_id, :trusted_attestation_types]

  defstruct [
    :bytes,
    :user,
    :origin,
    :rp_id,
    :user_verified_required,
    :exp,
    :token_binding_status,
    :allow_credentials,
    :trusted_attestation_types
  ]

  @type t :: %__MODULE__{
    bytes: binary(),
    user: Wax.User.t(),
    origin: String.t(),
    rp_id: String.t(),
    user_verified_required: boolean(),
    exp: non_neg_integer() | nil,
    token_binding_status: any(),
    allow_credentials: [binary()],
    trusted_attestation_types: [Wax.Attestation.type()] |
    (Wax.Attestation.result() -> boolean())
  }

  @spec new(Wax.User.t(), Wax.parsed_opts()) :: t()
  def new(user,
          allow_credentials \\ [],
          %{origin: origin,
            rp_id: rp_id,
            user_verified_required: uvr,
            trusted_attestation_types: trusted_attestation_types
          })
  do
    %__MODULE__{
      bytes: random_bytes(),
      user: user,
      origin: origin,
      rp_id: rp_id,
      user_verified_required: uvr,
      allow_credentials: allow_credentials,
      trusted_attestation_types: trusted_attestation_types
    }
  end

  @spec random_bytes() :: binary
  def random_bytes() do
    :crypto.strong_rand_bytes(32)
  end
end
