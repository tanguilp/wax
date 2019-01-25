defmodule Wax.CoseKey do
  @kty 1
  @kid 2
  @alg 3
  @key_ops 4
  @base_IV 5

  @key_type_OKP 1
  @key_type_EC2 2
  @key_type_RSA 3
  @key_type_symmetric 4

  @key_type_string %{
    @key_type_OKP => "OKP",
    @key_type_EC2 => "EC2",
    @key_type_RSA => "RSA",
    @key_type_symmetric => "Symmetric"
  }

  @es512 -36
  @es384 -35
  @es256 -7

  @cose_alg_string %{
    -259 => "RS512 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
    -258 => "RS384 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
    -257 => "RS256 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
    -42 => "RSAES-OAEP w/ SHA-512",
    -41 => "RSAES-OAEP w/ SHA-256",
    -40 => "RSAES-OAEP w/ RFC 8017 default parameters",
    -39 => "PS512",
    -38 => "PS384",
    -37 => "PS256",
    -36 => "ES512",
    -35 => "ES384",
    -34 => "ECDH-SS + A256KW",
    -33 => "ECDH-SS + A192KW",
    -32 => "ECDH-SS + A128KW",
    -31 => "ECDH-ES + A256KW",
    -30 => "ECDH-ES + A192KW",
    -29 => "ECDH-ES + A128KW",
    -28 => "ECDH-SS + HKDF-512",
    -27 => "ECDH-SS + HKDF-256",
    -26 => "ECDH-ES + HKDF-512",
    -25 => "ECDH-ES + HKDF-256",
    -13 => "direct+HKDF-AES-256",
    -12 => "direct+HKDF-AES-128",
    -11 => "direct+HKDF-SHA-512",
    -10 => "direct+HKDF-SHA-256",
    -8 => "EdDSA",
    -7 => "ES256",
    -6 => "direct",
    -5 => "A256KW",
    -4 => "A192KW",
    -3 => "A128KW",
    1 => "A128GCM",
    2 => "A192GCM",
    3 => "A256GCM",
    4 => "HMAC 256/64",
    5 => "HMAC 256/256",
    6 => "HMAC 384/384",
    7 => "HMAC 512/512",
    10 => "AES-CCM-16-64-128",
    11 => "AES-CCM-16-64-256",
    12 => "AES-CCM-64-64-128",
    13 => "AES-CCM-64-64-256",
    14 => "AES-MAC 128/64",
    15 => "AES-MAC 256/64",
    24 => "ChaCha20/Poly1305",
    25 => "AES-MAC 128/128",
    26 => "AES-MAC 256/128",
    30 => "AES-CCM-16-128-128",
    31 => "AES-CCM-16-128-256",
    32 => "AES-CCM-64-128-128",
    33 => "AES-CCM-64-128-256"
  }

  @cose_ec_string %{
    1 => "P-256",
    2 => "P-384",
    3 => "P-521",
    4 => "X25519",
    5 => "X448",
    6 => "Ed25519",
    7 => "Ed448"
  }

  @cose_ec_named_curves %{
    1 => :secp256r1,
    2 => :secp384r1,
    3 => :secp521r1
  }

  @type t :: %{required(integer()) => integer}

  @type cose_alg :: integer()

  @spec pretty_map(t()) :: map()

  def pretty_map(%{@kty => @key_type_OKP, @alg => alg} = key) do
    %{
      kty: @key_type_string[@key_type_OKP],
      alg: @cose_alg_string[alg],
      crv: @cose_ec_string[key[-1]],
      x: key[-2]
    }
  end

  def pretty_map(%{@kty => @key_type_EC2, @alg => alg} = key) do
    %{
      kty: @key_type_string[@key_type_EC2],
      alg: @cose_alg_string[alg],
      crv: @cose_ec_string[key[-1]],
      x: key[-2],
      y: key[-3]
    }
  end

  def pretty_map(%{@kty => @key_type_RSA, @alg => alg} = key) do
    %{
      kty: @key_type_string[@key_type_RSA],
      alg: @cose_alg_string[alg],
      n: key[-1],
      e: key[-2]
    }
  end

  def pretty_map(%{@kty => @key_type_symmetric, @alg => alg}) do
    %{
      kty: @key_type_string[@key_type_RSA],
      alg: @cose_alg_string[alg],
    }
  end

  @spec verify(t(), binary(), binary()) :: :ok | {:error, any()}

  def verify(%{@kty => @key_type_EC2, @alg => @es256, -1 => crv, -2 => x, -3 => y}, msg, sig)
    when crv in unquote(Map.keys(@cose_ec_named_curves))
  do
    key = {{:ECPoint, <<4>> <> x <> y}, {:namedCurve, @cose_ec_named_curves[crv]}}

    if :public_key.verify(msg, :sha256, sig, key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  def verify(%{@kty => @key_type_EC2, @alg => @es384, -1 => crv, -2 => x, -3 => y}, msg, sig)
    when crv in unquote(Map.keys(@cose_ec_named_curves))
  do
    key = {{:ECPoint, <<4>> <> x <> y}, {:namedCurve, @cose_ec_named_curves[crv]}}

    if :public_key.verify(msg, :sha384, sig, key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  def verify(%{@kty => @key_type_EC2, @alg => @es512, -1 => crv, -2 => x, -3 => y}, msg, sig)
    when crv in unquote(Map.keys(@cose_ec_named_curves))
  do
    key = {{:ECPoint, <<4>> <> x <> y}, {:namedCurve, @cose_ec_named_curves[crv]}}

    if :public_key.verify(msg, :sha512, sig, key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  #FIXME: implement for other key types

  @spec erlang_public_key(map) :: :public_key.rsa_public_key() | :public_key.ec_public_key()

  def erlang_public_key(%{@kty => @key_type_EC2, -1 => curve, -2 => x, -3 => y}) do
    {
      {:ECPoint, <<4>> <> x <> y},
      # here we convert the curve name to its OID since certificates against which
      # it may be compared use OIDs
      {:namedCurve, :pubkey_cert_records.namedCurves(@cose_ec_named_curves[curve])}
    }
  end

  def erlang_public_key(%{@kty => @key_type_RSA, -1 => n, -2 => e}) do
    {:RSAPublicKey, n, e}
  end
end
