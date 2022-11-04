defmodule Wax.AuthenticatorDataTest do
  use ExUnit.Case, async: true

  alias Wax.AuthenticatorData

  @authenticator_data_with_aaguid %Wax.AuthenticatorData{
    rp_id_hash:
      <<73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174,
        185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99>>,
    flag_user_present: true,
    flag_user_verified: false,
    flag_attested_credential_data: true,
    flag_extension_data_included: false,
    sign_count: 0,
    attested_credential_data: %Wax.AttestedCredentialData{
      aaguid: <<104, 8, 128, 119, 227, 165, 109, 92, 65, 81, 189, 91, 34, 105, 96, 203>>,
      credential_id:
        <<144, 128, 16, 67, 212, 146, 114, 231, 245, 224, 225, 25, 63, 103, 176, 195, 165, 29,
          101, 10, 232, 227, 137, 206, 228, 73, 175, 115, 203, 137, 199, 9, 13, 168, 183, 179,
          221, 200, 234, 222, 194>>,
      credential_public_key: %{
        -3 =>
          <<7, 2, 79, 132, 254, 40, 128, 231, 243, 193, 227, 243, 226, 30, 189, 250, 78, 68, 151,
            133, 237, 53, 36, 14, 217, 131, 203, 248, 199, 251, 12, 199>>,
        -2 =>
          <<229, 166, 85, 41, 2, 161, 235, 30, 108, 134, 177, 194, 25, 234, 99, 2, 241, 178, 6,
            250, 170, 177, 74, 132, 80, 159, 20, 103, 139, 159, 201, 48>>,
        -1 => 1,
        1 => 2,
        3 => -7
      }
    },
    extensions: nil,
    raw_bytes:
      <<73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174,
        185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99, 65, 0, 0, 0, 0, 0, 0, 0, 0>>
  }
  @authenticator_data_without_aaguid %Wax.AuthenticatorData{
    rp_id_hash:
      <<73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174,
        185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99>>,
    flag_user_present: true,
    flag_user_verified: false,
    flag_attested_credential_data: true,
    flag_extension_data_included: false,
    sign_count: 0,
    attested_credential_data: %Wax.AttestedCredentialData{
      aaguid: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
      credential_id:
        <<144, 128, 16, 67, 212, 146, 114, 231, 245, 224, 225, 25, 63, 103, 176, 195, 165, 29,
          101, 10, 232, 227, 137, 206, 228, 73, 175, 115, 203, 137, 199, 9, 13, 168, 183, 179,
          221, 200, 234, 222, 194>>,
      credential_public_key: %{
        -3 =>
          <<7, 2, 79, 132, 254, 40, 128, 231, 243, 193, 227, 243, 226, 30, 189, 250, 78, 68, 151,
            133, 237, 53, 36, 14, 217, 131, 203, 248, 199, 251, 12, 199>>,
        -2 =>
          <<229, 166, 85, 41, 2, 161, 235, 30, 108, 134, 177, 194, 25, 234, 99, 2, 241, 178, 6,
            250, 170, 177, 74, 132, 80, 159, 20, 103, 139, 159, 201, 48>>,
        -1 => 1,
        1 => 2,
        3 => -7
      }
    },
    extensions: nil,
    raw_bytes:
      <<73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174,
        185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99, 65, 0, 0, 0, 0, 0, 0, 0, 0>>
  }

  describe ".get_aaguid/2" do
    test "returns aaguid when present" do
      assert is_binary(AuthenticatorData.get_aaguid(@authenticator_data_with_aaguid))
    end

    test "returns nil if there's no aaguid" do
      assert AuthenticatorData.get_aaguid(@authenticator_data_without_aaguid) == nil
    end
  end
end
