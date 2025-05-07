defmodule Wax.ChallengeTest do
  use ExUnit.Case, async: true

  alias Wax.Challenge

  describe "new/1" do
    test "generates bytes" do
      challenge = Challenge.new([])

      assert byte_size(challenge.bytes) == 32
    end

    test "does not override bytes when provided as an option" do
      challenge = Challenge.new(bytes: "abcd")

      assert challenge.bytes == "abcd"
    end
  end
end
