defmodule Wax.Utils.Timestamp.Real do
  @moduledoc false

  @behaviour Wax.Utils.Timestamp

  @impl true
  def get_timestamp() do
    :os.system_time(:second)
  end
end
