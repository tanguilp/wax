defmodule Wax.Attestation do
  @typedoc """
  The attestation statement
  """
  @type statement :: map()

  @typedoc """
  The attestation type
  """
  @type type ::
          :basic
          | :self
          | :attca
          | :ecdaa
          | :uncertain
          | :none

  @typedoc """
  The attestation statement format
  """
  @type statement_format ::
          :packed
          | :tpm
          | :android_key
          | :android_safetynet
          | :fido_u2f
          | :none

  @typedoc """
  The attestation path
  """
  @type trust_path :: [binary()] | binary()

  @type result :: {type(), trust_path() | nil, Wax.Metadata.statement() | nil}

  @spec verify(
          statement(),
          format :: String.t(),
          Wax.AuthenticatorData.t(),
          Wax.ClientData.hash(),
          Wax.Challenge.t()
        ) :: {:ok, result()} | {:error, Exception.t()}

  def verify(att_statement, "none", auth_data, client_data_hash, challenge) do
    Wax.AttestationStatementFormat.None.verify(
      att_statement,
      auth_data,
      client_data_hash,
      challenge
    )
  end

  def verify(att_statement, "fido-u2f", auth_data, client_data_hash, challenge) do
    Wax.AttestationStatementFormat.FIDOU2F.verify(
      att_statement,
      auth_data,
      client_data_hash,
      challenge
    )
  end

  def verify(att_statement, "android-key", auth_data, client_data_hash, challenge) do
    Wax.AttestationStatementFormat.AndroidKey.verify(
      att_statement,
      auth_data,
      client_data_hash,
      challenge
    )
  end

  def verify(att_statement, "android-safetynet", auth_data, client_data_hash, challenge) do
    Wax.AttestationStatementFormat.AndroidSafetynet.verify(
      att_statement,
      auth_data,
      client_data_hash,
      challenge
    )
  end

  def verify(att_statement, "tpm", auth_data, client_data_hash, challenge) do
    Wax.AttestationStatementFormat.TPM.verify(
      att_statement,
      auth_data,
      client_data_hash,
      challenge
    )
  end

  def verify(att_statement, "packed", auth_data, client_data_hash, challenge) do
    Wax.AttestationStatementFormat.Packed.verify(
      att_statement,
      auth_data,
      client_data_hash,
      challenge
    )
  end

  def verify(_, _, _, _, _) do
    {:error, %Wax.UnsupportedAttestationFormatError{}}
  end
end
