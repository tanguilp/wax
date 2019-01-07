defmodule Wax.CredentialStore.ETS do
  @behaviour Wax.CredentialStore

  @impl true
  def register(user, credential_id, cose_key) do
    create_table()

    :ets.insert(:wax_credential_store, {user, credential_id, cose_key})

    :ok
  end

  @impl true
  def get_key(user, credential_id) do
    create_table()

    case :ets.match(:wax_credential_store, {user, credential_id, :'$1'}) do
      [[cose_key]] ->
        {:ok, cose_key}

      _ ->
        {:error, :key_not_found}
    end
  end

  defp create_table() do
    if :ets.info(:wax_credential_store) == :undefined do
      :ets.new(:wax_credential_store, [:bag, :public, :named_table])
    end
  end
end
