## CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [0.2.0] #FIXME date

### Added

- [Wax] When verifying trust root, `Wax.register/3` checks the authenticator status against the
values whitelisted by the `:acceptable_authenticator_statuses` option
- [Wax] Added support for PS256, PS384, PS512 and EdDSA signature schemes
- [Wax] Added timeout field and verification to challenges

### Changed

- [Wax] `Wax.register/3` and `Wax.authenticate/5` signatures change and now return the whole
authenticator data.

### Fixed

- [Wax.Metadata] TOC JWS signature is verified against FIDO Fundation certificate
