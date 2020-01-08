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
  The attestation path
  """
  @type trust_path :: [binary()] | binary() | nil

  @type result ::
  {__MODULE__.type(), __MODULE__.trust_path() | nil, Wax.Metadata.Statement.t() | nil}

  @type attestation_statement_format_verify_fun ::
  (
    Wax.Attestation.statement(),
    Wax.AuthenticatorData.t(),
    Wax.ClientData.hash(),
    Wax.Challenge.t() ->
      {:ok, __MODULE__.result()} | {:error, any()}
  )

  @doc false

  @spec statement_verify_fun(binary()) ::
    {:ok, attestation_statement_format_verify_fun} | {:error, any()}

  def statement_verify_fun("none") do
    {:ok, &Wax.AttestationStatementFormat.None.verify/4}
  end

  def statement_verify_fun("fido-u2f") do
    {:ok, &Wax.AttestationStatementFormat.FIDOU2F.verify/4}
  end

  def statement_verify_fun("android-key") do
    {:ok, &Wax.AttestationStatementFormat.AndroidKey.verify/4}
  end

  def statement_verify_fun("android-safetynet") do
    {:ok, &Wax.AttestationStatementFormat.AndroidSafetynet.verify/4}
  end

  def statement_verify_fun("tpm") do
    {:ok, &Wax.AttestationStatementFormat.TPM.verify/4}
  end

  def statement_verify_fun("packed") do
    {:ok, &Wax.AttestationStatementFormat.Packed.verify/4}
  end

  def statement_verify_fun(_) do
    {:error, :unsupported_statement_format}
  end
end
