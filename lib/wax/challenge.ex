defmodule Wax.Challenge do
  @enforce_keys [
    :type,
    :bytes,
    :origin,
    :rp_id,
    :issued_at
  ]

  defstruct [
    :type,
    :bytes,
    :origin,
    :rp_id,
    :token_binding_status,
    :issued_at,
    acceptable_authenticator_statuses: [
      "FIDO_CERTIFIED",
      "FIDO_CERTIFIED_L1",
      "FIDO_CERTIFIED_L1plus",
      "FIDO_CERTIFIED_L2",
      "FIDO_CERTIFIED_L2plus",
      "FIDO_CERTIFIED_L3",
      "FIDO_CERTIFIED_L3plus"
    ],
    android_key_allow_software_enforcement: false,
    allow_credentials: [],
    attestation: "none",
    silent_authentication_enabled: false,
    timeout: 120,
    trusted_attestation_types: [:none, :self, :basic, :uncertain, :attca, :anonca],
    user_verification: "preferred",
    verify_trust_root: true
  ]

  @type t :: %__MODULE__{
          type: :attestation | :authentication,
          attestation: String.t(),
          bytes: binary(),
          origin: String.t(),
          rp_id: String.t(),
          user_verification: String.t(),
          token_binding_status: any(),
          allow_credentials: [{Wax.AuthenticatorData.credential_id(), Wax.CoseKey.t()}],
          trusted_attestation_types: [Wax.Attestation.type()],
          verify_trust_root: boolean(),
          acceptable_authenticator_statuses: [String.t()],
          issued_at: integer(),
          timeout: non_neg_integer(),
          android_key_allow_software_enforcement: boolean(),
          silent_authentication_enabled: boolean()
        }

  @opt_names [
    :attestation,
    :origin,
    :rp_id,
    :user_verification,
    :trusted_attestation_types,
    :verify_trust_root,
    :acceptable_authenticator_statuses,
    :timeout,
    :android_key_allow_software_enforcement,
    :silent_authentication_enabled
  ]

  @doc false

  @spec new(Wax.opts()) :: t()
  def new(opts) do
    opts =
      opts
      |> Keyword.put(:bytes, random_bytes())
      |> Keyword.put(:issued_at, :erlang.monotonic_time(:second))

    opts_from_env = Application.get_all_env(:wax_) |> Keyword.take(@opt_names)

    opts = Keyword.merge(opts, opts_from_env)

    unless is_binary(opts[:origin]),
      do: raise("Missing mandatory parameter `origin` (String.t())")

    unless URI.parse(opts[:origin]).host == "localhost" or
             URI.parse(opts[:origin]).scheme == "https" do
      raise "Invalid origin `#{opts[:origin]}` (must be either https scheme or `localhost`)"
    end

    unless is_binary(opts[:rp_id]) or opts[:rp_id] == :auto do
      raise "Missing mandatory parameter `rp_id` (String.t())"
    end

    opts =
      if opts[:rp_id] == :auto,
        do: Keyword.put(opts, :rp_id, URI.parse(opts[:origin]).host),
        else: opts

    struct(__MODULE__, opts)
  end

  defp random_bytes() do
    :crypto.strong_rand_bytes(32) |> Base.encode16()
  end
end
