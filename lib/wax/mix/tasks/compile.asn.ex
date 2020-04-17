defmodule Mix.Tasks.Compile.Asn do
  use Mix.Task.Compiler

  @impl true
  def run(_args) do
    File.mkdir("src")

    Path.wildcard("asn1/*")
    |> Enum.each(fn asn1_file ->
      asn1_file
      |> String.to_charlist()
      |> :asn1ct.compile(outdir: 'src/')
    end)

    {:ok, []}
  end
end
