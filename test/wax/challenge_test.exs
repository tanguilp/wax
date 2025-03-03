defmodule Wax.ChanllengeTest do
  use ExUnit.Case, async: true

  alias Wax.Challenge

  test "generates bytes" do
    assert Challenge.new([]).bytes
  end

  test "does not override bytes when provided as an option" do
    assert %{bytes: "abcd"} = Challenge.new(bytes: "abcd")
  end
end
