use Mix.Config

config :wax_,
  origin: "http://localhost:4000",
  rp_id: :auto,
  metadata_update_interval: 3600,
  allowed_attestation_types: [:basic, :uncertain, :attca, :self]
