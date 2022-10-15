defmodule Wax.Utils.Timestamp.Real do
  @moduledoc false

  @spec get_timestamp() :: non_neg_integer()
  def get_timestamp() do
    :os.system_time(:second)
  end
end
