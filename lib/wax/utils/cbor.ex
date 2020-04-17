defmodule Wax.Utils.CBOR do
  @moduledoc false

  @doc """
  Decodes a CBOR binary object

  In addition to `CBOR.decode/1`, it converts `%CBOR.Tag{tag: :bytes, value: <<...>>}` to
  a binary field.
  """

  @spec decode(binary()) :: {:ok, any(), binary()} | {:error, atom()}
  def decode(cbor) do
    with {:ok, cbor, rest} <- CBOR.decode(cbor) do
      {:ok, reduce_binaries(cbor), rest}
    end
  end

  defp reduce_binaries(%CBOR.Tag{tag: :bytes, value: bytes}) do
    bytes
  end

  defp reduce_binaries(%{} = map) do
    Enum.reduce(map, %{}, fn {k, v}, acc -> Map.put(acc, k, reduce_binaries(v)) end)
  end

  defp reduce_binaries([_ | _] = list) do
    for elt <- list, do: reduce_binaries(elt)
  end

  defp reduce_binaries(any_value) do
    any_value
  end
end
