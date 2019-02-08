# Wax

WebAuthn library for elixir

<img src="wax.png" width="128">

Goal: provides with a *comprehensive* implementation of WebAuthn on the server side
(*Relying party* or RP in the WebAuthn terminology).

## Demo app

You can try out and study WebAuthn authentication with Wax thanks to the
[wax_demo](https://github.com/tanguilp/wax_demo) test application.

See alos a video demonstration of an authentication flow which allows replacing the password
authentication scheme by a WebAuthn password-less authentication:

[![Demo screenshot](https://raw.githubusercontent.com/tanguilp/wax_demo/master/assets/static/images/demo_screenshot.png)](https://rutube.ru/video/c1d10dbcdea2403e3760e603d6da7ac2/)

## Installation

Add the following line to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:wax, github: "tanguilp/wax", tag: "0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)

## Support of FIDO2

[2. Registration and Attestations](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#registration-and-attestation)
- [x] **Mandatory**: registration support
- [x] **Mandatory**: random challenge
- [2.1. Validating Attestation](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#validating-attestation)
  - [x] **Mandatory**: attestation validation
  - [x] **Mandatory**: attestation certificate chains (note: can be disabled through an option)
  - [x] **Mandatory**: validation of attestation through the FIDO Metadata Service 
- [2.2. Attestation Types](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#attestation-types)
  - [x] **Mandatory**: basic attestation
  - [x] **Mandatory**: self attestation
  - [x] **Mandatory**: private CA attestation
  - [ ] *Optional*: elliptic curve direct anonymous attestation
- [2.3. Attestation Formats](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#attestation-formats)
  - [x] **Mandatory**: packed attestation
  - [x] **Mandatory**: TPM attestation
  - [x] *Optional*: Android key attestation
  - [x] **Mandatory**: U2F attestation
  - [x] **Mandatory**: Android Safetynet attestation

[3. Authentication and Assertions](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#authn-and-assertion)
  - [x] **Mandatory**: authentication
  - [x] **Mandatory**: random challenge
  - [x] **Mandatory**: assertion signature validation
  - [x] **Mandatory**: TUP verification (note: and also user verified, through an option)

[4. Communication Channel Requirements](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#communication-channel-requirements)
  - [ ] *Optional*: TokenBinding support

[5. Extensions](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#extensions)
  - [x] **Mandatory**: registration and authentication support without extension
  - [ ] *Optional*: extension support
  - [ ] *Optional*: appid extension support

[6. Other](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#other)
  - [x] **Mandatory**: RS1 (RSASSA-PKCS1-v1_5 w/ SHA-1) algorithm support
  - [x] **Mandatory**: RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256) algorithm support
  - [x] *Optional*: RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384) algorithm support
  - [x] *Optional*: RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512) algorithm support
  - [ ] *Optional*: PS256 (RSASSA-PSS w/ SHA-256) algorithm support
  - [ ] *Optional*: PS384 (RSASSA-PSS w/ SHA-384) algorithm support
  - [ ] *Optional*: PS512 (RSASSA-PSS w/ SHA-512) algorithm support
  - [x] **Mandatory**: ES256 (ECDSA using P-256 and SHA-256) algorithm support
  - [x] *Optional*: ES384 (ECDSA using P-384 and SHA-384) algorithm support
  - [x] *Optional*: ES512 (ECDSA using P-521 and SHA-512) algorithm support
  - [ ] *Optional*: EdDSA algorithm support
  - [ ] *Optional*: ES256K (ECDSA using P-256K and SHA-256) algorithm support
  - [-] **Mandatory**: compliance with the FIDO privacy principles (note: out-of-scope, to be implemented by the server using the Wax library)

[7. Transport Binding Profile](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#transport-binding-profile)
  - [ ] API implementation
