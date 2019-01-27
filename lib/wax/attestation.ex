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
  @type trust_path :: any() #FIXME

  @type attestation_statement_format_verify_fun ::
  (
    Wax.Attestation.statement(), Wax.AuthData.t(), Wax.ClientData.hash() ->
      {:ok, {type(), trust_path()}} | {:error, any()}
  )

  @spec statement_verify_fun(binary()) ::
    {:ok, attestation_statement_format_verify_fun} | {:error, any()}

  #FIXME: the spec says we should US-ASCII => is that ok to pattern-match like this?
  # Pattern-matching should be performed on binaries, but should be checked
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
    {:ok, &Wax.AttestationStatementFormat.AndroidKey.verify/4}
  end

  def statement_verify_fun(_) do
    {:error, :unsupported_statement_format}
  end
end
