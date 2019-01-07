defmodule Wax.CredentialStore do
  @callback register(Wax.User.t(), Wax.AuthData.credential_id(), Wax.CoseKey.t())
    :: :ok | {:error, any()}

  @callback get_key(Wax.User.t(), Wax.AuthData.credential_id())
    :: {:ok, Wax.CoseKey.t()} | {:error, any()}
end
