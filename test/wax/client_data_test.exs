defmodule Wax.ClientDataTest do
  use ExUnit.Case, async: true

  alias Wax.ClientData

  @challenge "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaY"

  defp client_data(overrides) do
    %{"type" => "webauthn.create", "challenge" => @challenge, "origin" => "http://localhost:4000"}
    |> Map.merge(overrides)
    |> Jason.encode!()
  end

  test "parses valid client data" do
    assert {:ok,
            %ClientData{type: :create, origin: "http://localhost:4000", challenge: challenge}} =
             ClientData.parse_raw_json(client_data(%{}))

    assert challenge == Base.url_decode64!(@challenge, padding: false)
  end

  test "returns an error when the JSON is not an object" do
    for json <- ["[]", ~s("webauthn.create"), "1", "null"] do
      assert {:error, %Wax.InvalidClientDataError{reason: :malformed_json}} =
               ClientData.parse_raw_json(json)
    end
  end

  test "returns an error when the type is unknown or missing" do
    for type <- ["webauthn.unknown", 1, nil] do
      assert {:error, %Wax.InvalidClientDataError{reason: :invalid_type}} =
               ClientData.parse_raw_json(client_data(%{"type" => type}))
    end
  end

  test "returns an error when the challenge is not base64url encoded" do
    for challenge <- ["not base64url!", 1, nil] do
      assert {:error, %Wax.InvalidClientDataError{reason: :invalid_challenge}} =
               ClientData.parse_raw_json(client_data(%{"challenge" => challenge}))
    end
  end

  test "returns an error when the origin is not a string" do
    for origin <- [1, nil] do
      assert {:error, %Wax.InvalidClientDataError{reason: :invalid_origin}} =
               ClientData.parse_raw_json(client_data(%{"origin" => origin}))
    end
  end
end
