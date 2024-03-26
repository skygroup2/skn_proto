defmodule ProxyEx do
  @moduledoc """
  `GunEx` provide api to make socket via proxy
  """
  @default_connect_timeout 30_000

  @doc """
    TCP socket API
  """
  def connect(dst_host, port, options) do
    connect(dst_host, port, options, @default_connect_timeout)
  end

  def connect(dst_host, port, options, timeout) do
    host = if is_binary(dst_host), do: :erlang.binary_to_list(dst_host), else: dst_host
    cond do
      options[:socks5_host] != nil ->
        # socks5_host, socks5_port, (socks5_transport), socks5_user, socks5_pass, (socks5_resolve)
        case :gun_socks5_proxy.connect(host, port, options, timeout) do
          {:ok, {_, socket}} ->
            {:ok, socket}
          exp ->
            exp
        end
      options[:connect_host] != nil and options[:connect_port] != nil ->
        proxy_host = options[:connect_host]
        proxy_port = options[:connect_port]
        connect_host = if is_tuple(host), do: :inet.ntoa(host), else: host
        options = List.keyreplace options, :connect_host, 0, {:connect_host, connect_host}
        options = List.keyreplace options, :connect_port, 0, {:connect_port, port}
        case :gun_http_proxy.connect(proxy_host, proxy_port, options, timeout) do
          {:ok, {_, socket}} ->
            {:ok, socket}
          exp ->
            exp
        end
      true ->
        host_n = case :inet.parse_ipv4_address(host) do
          {:ok, v} -> v
          _ -> host
        end
        :gen_tcp.connect(host_n, port, options[:tcp_opt], timeout)
    end
  end
end