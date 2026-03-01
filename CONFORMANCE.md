# FIDO Alliance Conformance

This document describes a practical workflow to run FIDO Alliance server
conformance tests against a fork of `wax`.

## 1. Fork setup

If you already have a GitHub fork, wire remotes like this:

```bash
git remote rename origin upstream
git remote add origin https://github.com/<your-user>/wax.git
git fetch --all --prune
git checkout -b conformance-ready
```

`upstream` should point to `tanguilp/wax`, and `origin` to your fork.

## 2. Local build baseline

From the `wax` repo:

```bash
mix deps.get
mix test
```

On OTP 28, this repo should compile and run tests with:

- `19 tests, 0 failures`

## 3. Test server for official suite

The official FIDO Alliance conformance tool is private and must be obtained
through FIDO Alliance certification access.

The test harness used by this project is:

- `https://github.com/tanguilp/wax_fido_test_suite_server`

Clone and run it separately, then point the conformance tool to that server URL.

## 4. Required conformance-specific configuration

Some TPM conformance tests use a fake manufacturer ID (`id:FFFFF1D0`).
Wax can now enable this through configuration instead of source edits:

```elixir
config :wax_,
  tpm_allow_conformance_fake_manufacturer: true
```

Recommended conformance-related settings in the test server:

```elixir
config :wax_,
  origin: "http://localhost:4000",
  rp_id: :auto,
  metadata_dir: :wax_fido_test_suite_server,
  tpm_allow_conformance_fake_manufacturer: true
```

## 5. Run the official suite

In the FIDO conformance tool UI:

1. Open `FIDO2 Tests`.
2. Download/import server metadata and place it in the server's configured metadata directory.
3. Set `Server URL` to your running server endpoint.
4. Run server tests (typically excluding metadata tests unless your scenario requires them).

## 6. Evidence of pass/fail

To claim conformance, keep artifacts from the official tool run:

- total test count
- pass/fail summary
- exported report/log from the tool
- tested `wax` commit SHA

Without these artifacts, conformance status should be considered unverified.
