defmodule Wax.Utils.Timestamp.TimeTravel do
  @moduledoc false

  @spec get_timestamp() :: non_neg_integer()
  def get_timestamp() do
    if Process.get(:mock_time) do
      Process.get(:mock_time)
    else
      :os.system_time(:second)
    end
  end

  @spec set_timestamp(non_neg_integer()) :: no_return()
  def set_timestamp(timestamp) do
    Process.put(:mock_time, timestamp)
  end
end
