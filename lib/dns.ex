defmodule DNS do
  def lookup(name, record \\ :a, timeout \\ 5000) do
    name = if is_binary(name), do: :erlang.binary_to_list(name), else: name

    case :inet_res.getbyname(name, record, timeout) do
      {:ok, {:hostent, _name, [], :inet, _version, ips}} ->
        Enum.map(ips, fn x -> :erlang.iolist_to_binary(:inet.ntoa(x)) end)

      _ ->
        []
    end
  end
end
