defmodule Wax.Utils.Timestamp do
  @moduledoc false

  @adapter if Mix.env() == :test,
             do: Wax.Utils.Timestamp.TimeTravel,
             else: Wax.Utils.Timestamp.Real

  @spec get_timestamp() :: non_neg_integer()

  def get_timestamp do
    @adapter.get_timestamp()
  end
end
