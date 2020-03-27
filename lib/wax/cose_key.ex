defmodule Wax.CoseKey do
  @kty 1
  @alg 3
  @curve -1

  @key_type_OKP 1
  @key_type_EC2 2
  @key_type_RSA 3

  @cose_alg_string %{
    -65535 => "RSASSA-PKCS1-v1_5 w/ SHA-1",
    -259 => "RS512 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
    -258 => "RS384 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
    -257 => "RS256 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
    -46 => "ES256K",
    -39 => "PS512",
    -38 => "PS384",
    -37 => "PS256",
    -36 => "ES512",
    -35 => "ES384",
    -8 => "EdDSA",
    -7 => "ES256",
  }

  @pss_algs [-39, -38, -37]

  @cose_ec_named_curves %{
    1 => :secp256r1,
    2 => :secp384r1,
    3 => :secp521r1,
    6 => :ed25519,
    7 => :ed448,
    8 => :secp256k1
  }

  @type t :: %{required(integer()) => integer}

  @type cose_alg :: integer()

  @doc """
  Returns the list of supported algorithms

      iex> Wax.CoseKey.supported_algs()
      %{
        -65535 => "RSASSA-PKCS1-v1_5 w/ SHA-1",
        -259 => "RS512 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
        -258 => "RS384 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
        -257 => "RS256 (TEMPORARY - registered 2018-04-19, expires 2019-04-19)",
        -42 => "RSAES-OAEP w/ SHA-512",
        -41 => "RSAES-OAEP w/ SHA-256",
        -39 => "PS512",
        -38 => "PS384",
        -37 => "PS256",
        -36 => "ES512",
        -35 => "ES384",
        -7 => "ES256"
      }
  """
  @spec supported_algs() :: %{required(cose_alg()) => String.t()}
  def supported_algs() do
    @cose_alg_string
  end

  @doc """
  Verifies the signature of a message against a COSE key

  Use `supported_algs/0` to determine supported algorithms.
  """

  @spec verify(message :: binary(), t(), signature :: binary()) :: :ok | {:error, atom()}

  def verify(msg, %{@alg => alg} = cose_key, sig) when alg in @pss_algs do
    # Use PSS padding; requires workaround for https://bugs.erlang.org/browse/ERL-878
    {:RSAPublicKey, n, e} = to_erlang_public_key(cose_key)

    digest = to_erlang_digest(cose_key)

    if :crypto.verify(:rsa, digest, msg, sig, [e, n], rsa_padding: :rsa_pkcs1_pss_padding) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  def verify(msg, %{@alg => alg} = cose_key, sig) when alg in unquote(Map.keys(@cose_alg_string))
  do
    key = to_erlang_public_key(cose_key)

    digest = to_erlang_digest(cose_key)

    if :public_key.verify(msg, digest, sig, key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  def verify(_, _, _) do
    {:error, :unsupported_signature_algorithm}
  end

  @doc false

  @spec to_erlang_public_key(t()) :: :public_key.public_key()

  def to_erlang_public_key(%{@kty => @key_type_EC2, -1 => curve, -2 => x, -3 => y}) do
    {
      {:ECPoint, <<4>> <> x <> y},
      # here we convert the curve name to its OID since certificates against which
      # it may be compared use OIDs
      # :public_key functions will work the same independantly of the format
      {:namedCurve, :pubkey_cert_records.namedCurves(@cose_ec_named_curves[curve])}
    }
  end

  def to_erlang_public_key(%{@kty => @key_type_RSA, -1 => n, -2 => e}) do
    nb_bytes_n = byte_size(n)
    nb_bytes_e = byte_size(e)

    <<n_int::unsigned-big-integer-size(nb_bytes_n)-unit(8)>> = n
    <<e_int::unsigned-big-integer-size(nb_bytes_e)-unit(8)>> = e

    {:RSAPublicKey, n_int, e_int}
  end

  def to_erlang_public_key(%{@kty => @key_type_OKP, -1 => curve, -2 => x}) when curve in 6..7 do
    {:ed_pub, @cose_ec_named_curves[curve], x}
  end

  @doc false

  @spec to_erlang_digest(t()) :: atom()
  def to_erlang_digest(%{@alg => -65535}), do: :sha
  def to_erlang_digest(%{@alg => -259}), do: :sha512
  def to_erlang_digest(%{@alg => -258}), do: :sha384
  def to_erlang_digest(%{@alg => -257}), do: :sha256
  def to_erlang_digest(%{@alg => -46, @curve => 8}), do: :sha256
  def to_erlang_digest(%{@alg => -42}), do: :sha512
  def to_erlang_digest(%{@alg => -41}), do: :sha256
  def to_erlang_digest(%{@alg => -39}), do: :sha512
  def to_erlang_digest(%{@alg => -38}), do: :sha384
  def to_erlang_digest(%{@alg => -37}), do: :sha256
  def to_erlang_digest(%{@alg => -36}), do: :sha512
  def to_erlang_digest(%{@alg => -35}), do: :sha384
  def to_erlang_digest(%{@alg => -8, -1 => 6}), do: :sha256   #ed25519
  def to_erlang_digest(%{@alg => -8, -1 => 7}), do: :sha3_256 #ed448
  def to_erlang_digest(%{@alg => -7}), do: :sha256
end
