use Mix.Config

config :wax_,
  origin: "http://localhost:4000",
  rp_id: :auto,
  update_metadata: true,
  allowed_attestation_types: [:basic, :uncertain, :attca, :self],
  metadata_dir: "metadata/metadata/metadataStatements/"

# import_config "dev.secret.exs"
