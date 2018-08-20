defmodule TcpEx do
  @connect_timeout 75000

  def connect(dhost, port, options) do
    host = if is_binary(dhost), do: :erlang.binary_to_list(dhost), else: dhost
    cond do
      options[:socks5_host] != nil ->
        case :hackney_socks5.connect(host, port, options, @connect_timeout) do
          {:ok, {_, socket}} ->
            {:ok, socket}
          exp ->
            exp
        end
      options[:connect_host] != nil and options[:connect_port] != nil ->
        hostx = options[:connect_host]
        portx = options[:connect_port]
        options = List.keyreplace options, :connect_host, 0, {:connect_host, host}
        options = List.keyreplace options, :connect_port, 0, {:connect_port, port}
        case :hackney_http_connect.connect(hostx, portx, options, @connect_timeout) do
          {:ok, {_, socket}} ->
            {:ok, socket}
          exp ->
            exp
        end
      true ->
        hostx = case :inet.parse_ipv4_address(host) do
          {:ok, v} -> v
          _ -> host
        end
        :gen_tcp.connect(hostx, port, options, @connect_timeout)
    end
  end

  def send(sockfd, data) do
    :gen_tcp.send(sockfd, data)
  end

  def recv(sockfd, length) do
    recv(sockfd, length, 30_000)
  end

  def recv(sockfd, length, timeout) do
    :gen_tcp.recv(sockfd, length, timeout)
  end

  def controlling_process(sockfd, pid) do
    :gen_tcp.controlling_process(sockfd, pid)
  end

  def peername(sockfd) do
    :inet.peername(sockfd)
  end

  def setopts(sockfd, opts) do
    :inet.setopts(sockfd, opts)
  end

  def shutdown(sockfd, how) do
    :gen_tcp.shutdown(sockfd, how)
  end

  def close(sockfd) do
    if is_port(sockfd) do
      :gen_tcp.close(sockfd)
    end
  end

end