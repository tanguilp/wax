# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [0.6.1] - 2023-02-20

### Changed

- [Wax] External ASN1 compiler is used (through a new dependency) that should fix issue when
compiling Wax for the first time

## [0.6.0] - 2022-11-07

### Changed

- [Wax] `Wax.new_authentication_challenge/1` signature change to support *resident keys*
- [Wax] `Wax.authenticate/6` signature change to support *resident keys*

## [0.5.0] - 2022-11-04

### Changed

- [Wax] Requires OTP25+
- [Wax] Supports Apple Anonymous attestation
- [Wax] Returns metadata as a map conforming with
  [FIDO Metadata Statement](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html),
  and no longer Elixir structs
- [Wax] All returned errors are exceptions
- [Wax.Metadata] Wax now loads MDSv3 metadata, and no longer requires an access token
- [Wax.Metadata] The `tesla` library is no longer used

## [0.4.1] - 2021-05-18

### Fixed

- [Wax.Metadata] Update root certificate for TOC integrity checking following FIDO MDSv2 switch
to public PKI infrastructure

## [0.4.0] - 2020-09-26

### Changed

- [Wax.Metadata] Metadata retrieval now makes use of the Tesla library. **Beware**, Tesla's
default adapter is insecure (`:https`), so you **need to configure a secure adapter**, such as
Hackney, if you use MDSv2 metadata.

## [0.3.1] - 2020-09-21

### Fixed

- [Wax.Metadata.Statement] Added newly added user verification methods and attachment hints.
User verification method names **have been updated** to reflect the latest specification. See
`t:Wax.Metadata.Statement.user_verification_method/0` type for new values.

## [0.3.0] - 2020-09-18

### Changed

- [Wax] Renamed application to `:wax_` due to a name collision. **Do not forget** to rename
any `:wax` entry in your configuration files
- [Wax] secp256k1's COSE alg value set to new standardized value

## [0.2.1] - 2020-05-30

### Fixed

- [Wax.AttestationStatementFormat.TPM] Commented TPM manufacturer ID used only for testing with
the FIDO2 test suite

## [0.2.0] - 2020-04-17

### Added

- [Wax] When verifying trust root, `Wax.register/3` checks the authenticator status against
the values whitelisted by the `:acceptable_authenticator_statuses` option
- [Wax.CoseKey] Added support for PS256, PS384, PS512, EdDSA signature schemes and
ES256K (secp256k1 curve) signature algorithms
- [Wax.Challenge] Added timeout field and verification
- [Wax] Added `:android_key_allow_software_enforcement` option
- [Wax.Metadata] FIDO2 metadata TOC checked against CRLs (#12)
- [Wax] Added a mean to load metadata from a directory
- [Wax] Added `:silent_authentication_enabled` option

### Changed

- [Wax] `Wax.register/3` and `Wax.authenticate/5` signatures change and now return the
whole authenticator data.
- [Wax] the `:user_verified_required` option is replace by the `:user_verification` option

### Fixed

- [Wax.Metadata] TOC JWS signature is verified against FIDO Fundation certificate
