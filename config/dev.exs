import Config

config :wax_,
  origin: "http://localhost:4000",
  rp_id: :auto,
  update_metadata: true,
  allowed_attestation_types: [:basic, :uncertain, :attca, :self],
  metadata_dir: "priv/fido2_metadata/"

# import_config "dev.secret.exs"
