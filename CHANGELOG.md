## CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [0.2.0] #FIXME date

### Added

- [Wax] When verifying trust root, `Wax.register/3` checks the authenticator status against the
values whitelisted by the `:acceptable_authenticator_statuses` option
- [Wax.CoseKey] Added support for PS256, PS384, PS512 and EdDSA signature schemes
- [Wax.Challenge] Added timeout field and verification
- [Wax] Added `:android_key_allow_software_enforcement` option
- [Wax.Metadata] FIDO2 metadata TOC checked against CRLs (#12)

### Changed

- [Wax] `Wax.register/3` and `Wax.authenticate/5` signatures change and now return the whole
authenticator data.

### Fixed

- [Wax.Metadata] TOC JWS signature is verified against FIDO Fundation certificate
