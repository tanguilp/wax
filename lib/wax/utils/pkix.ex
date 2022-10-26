defmodule Wax.Utils.PKIX do
  @moduledoc false

  @typep cert_der :: binary()

  @spec path_valid?(
          root_cert :: cert_der() | [cert_der],
          rest_of_chain :: [cert_der],
          Keyword.t()
        ) :: boolean()
  def path_valid?(root_cert_or_certs, rest_of_chain, opts \\ [])

  def path_valid?(<<_::binary>> = root_cert, rest_of_chain, opts) do
    path_valid?([root_cert], rest_of_chain, opts)
  end

  def path_valid?(root_certs, rest_of_chain, opts) do
    cond do
      # A test in the suite checks if providing a full path fails
      match?({:ok, _}, :public_key.pkix_path_validation(hd(rest_of_chain), rest_of_chain, opts)) ->
        false

      # Won't validate with :public_key, but it's allowed by https://github.com/w3c/webauthn/pull/1509
      length(rest_of_chain) == 1 and hd(rest_of_chain) in root_certs ->
        true

      true ->
        Enum.any?(
          root_certs,
          &match?({:ok, _}, :public_key.pkix_path_validation(&1, [&1 | rest_of_chain], opts))
        )
    end
  end
end
