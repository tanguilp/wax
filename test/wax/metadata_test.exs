defmodule Wax.MetadataTest do
  use ExUnit.Case, async: true

  alias Wax.Metadata

  @test_metadata [
    %{
      "aaguid" => "00000000-0000-0000-0000-000000000001",
      "statusReports" => [
        %{
          "effectiveDate" => "2021-03-09",
          "status" => "FIDO_CERTIFIED_L2"
        },
        %{
          "effectiveDate" => "2020-09-18",
          "status" => "FIDO_CERTIFIED_L1"
        },
        %{
          "effectiveDate" => "2019-11-13",
          "status" => "NOT_FIDO_CERTIFIED"
        }
      ]
    },
    %{
      "aaguid" => "00000000-0000-0000-0000-000000000002",
      "statusReports" => [
        %{
          "effectiveDate" => "2022-07-15",
          "status" => "UPDATE_AVAILABLE"
        },
        %{
          "effectiveDate" => "2021-03-09",
          "status" => "FIDO_CERTIFIED_L2"
        },
        %{
          "effectiveDate" => "2020-09-18",
          "status" => "FIDO_CERTIFIED_L1"
        }
      ]
    },
    %{
      "aaguid" => "00000000-0000-0000-0000-000000000003",
      "statusReports" => [
        %{
          "effectiveDate" => "2022-07-15",
          "status" => "SELF_ASSERTION_SUBMITTED"
        },
        %{
          "status" => "FIDO_CERTIFIED_L1"
        },
        %{
          "effectiveDate" => "2020-09-18",
          "status" => "NOT_FIDO_CERTIFIED"
        }
      ]
    },
    %{
      "aaguid" => "00000000-0000-0000-0000-000000000004",
      "statusReports" => [
        %{
          "effectiveDate" => "2021-01-01",
          "status" => "FIDO_CERTIFIED_L2"
        },
        %{
          "effectiveDate" => "2022-01-01",
          "status" => "REVOKED"
        },
        %{
          "effectiveDate" => "2019-01-01",
          "status" => "FIDO_CERTIFIED_L1"
        }
      ]
    }
  ]

  setup do
    :persistent_term.put({Wax.Metadata, :mdsv3}, @test_metadata)

    []
  end

  describe ".get_by_aaguid/2" do
    test "returns an error when metadata does not exist" do
      challenge = Wax.new_registration_challenge()

      assert {:error, %Wax.MetadataStatementNotFoundError{}} =
               Metadata.get_by_aaguid(<<0::size(128)>>, challenge)
    end

    test "returns metadata when aaguid is valid and status accepted" do
      challenge = Wax.new_registration_challenge()

      assert {:ok, _} = Metadata.get_by_aaguid(<<1::size(128)>>, challenge)
    end

    test "returns an error when status is not accepted" do
      challenge =
        Wax.new_registration_challenge(
          acceptable_authenticator_statuses: ["FIDO_CERTIFIED_L3", "FIDO_CERTIFIED_L3plus"]
        )

      assert {:error, %Wax.AuthenticatorStatusNotAcceptableError{}} =
               Metadata.get_by_aaguid(<<1::size(128)>>, challenge)
    end

    test "ignores UPDATE_AVAILABLE statuses" do
      challenge = Wax.new_registration_challenge()

      assert {:ok, _} = Metadata.get_by_aaguid(<<2::size(128)>>, challenge)
    end

    test "considers status entry with no date the most recent" do
      challenge = Wax.new_registration_challenge()

      assert {:ok, _} = Metadata.get_by_aaguid(<<3::size(128)>>, challenge)
    end

    test "returns an error when authenticator is revoked, even if dates are not ordered" do
      challenge = Wax.new_registration_challenge()

      assert {:error, %Wax.AuthenticatorStatusNotAcceptableError{}} =
               Metadata.get_by_aaguid(<<4::size(128)>>, challenge)
    end
  end
end
