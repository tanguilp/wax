defmodule Wax.CredentialId do
  @typedoc """
  The binary representation of a credential id

  It is usually transmitted to a FIDO2 RP encoded as a base 64 string. One can decode it as
  follows:

  ```elixir
  Base.url_decode64!(credential_id, padding: false)
  ```

  or keep it and store it with its base64 format
  """

  @type t :: binary()
end
