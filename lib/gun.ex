defmodule GunEx do
  @connect_timeout 75000
  @doc """
    HTTP 1.1, HTTP 2.0 API
    opts:
      - retry: number of retries to connect
      - retry_timeout: non_neg_integer
      - connect_timeout: non_neg_integer
      - recv_timeout: non_neg_integer
      - proxy:
        + {:socks5, {127, 0, 0, 1}, 1080}
        + http://127.0.0.1:8080
        + {:connect, {127, 0, 0, 1}, 8080}
        + {{127, 0, 0, 1}, 8080}
      - proxy_auth: {u, p}
      - socks5_resolve: :local | :remote ( in case socks5)
      - protocols: [:http| :http2]
      - transport: tcp | tls
      - transport_opts  => [gen_tcp:connect_option()] | [ssl:connect_option()]
      - http_opts => #{}
      - http2_opts => #{}
      - ws_opts => #{}
  """
  def default_option(connect_timeout\\ 35000, recv_timeout\\ 20_000) do
    Gun.default_option(connect_timeout, recv_timeout)
  end

  def http_request(method, url, headers, body, opts, ref) do
    Gun.http_request(method, url, headers, body, opts, ref)
  end

  def http_close(ref, conn\\ nil) do
    Gun.http_close(ref, conn)
  end

  def decode_gzip(response) do
    decode_gzip(response.headers, response.body)
  end

  def decode_gzip(headers, body) when is_binary(body) and byte_size(body) > 0 do
    case List.keyfind(headers, "content-encoding", 0) do
      {"content-encoding", "gzip"} ->
        :zlib.gunzip(body)
      {"content-encoding", encoding} ->
        if String.contains?(encoding, "gzip") == true do
          :zlib.gunzip(body)
        else
          body
        end
      nil ->
        body
    end
  end

  def decode_gzip(_headers, body) do
    body
  end

  def get_rest(response) when is_binary(response) do
    if response == "" do
      %{}
    else
      Jason.decode!(response)
    end
  end

  def get_rest(%{status_code: code} = response) do
    case code do
      200 ->
        uz = decode_gzip(response)
        if uz == "" do
          %{}
        else
          Jason.decode!(uz)
        end
      _ ->
        throw({:error, response})
    end
  end

  def get_rest({:error, reason}) do
    throw({:error, reason})
  end

  def get_header_body(%{status_code: code, headers: headers} = response) do
    case code do
      200 ->
        {headers, decode_gzip(response)}
      _ ->
        throw({:error, response})
    end
  end

  def get_header_body({:error, reason}) do
    throw({:error, reason})
  end

  def get_body(%{status_code: code} = response) do
    case code do
      200 ->
        decode_gzip(response)
      _ ->
        throw({:error, response})
    end
  end

  def get_body({:error, reason}) do
    throw({:error, reason})
  end

  @doc """
    TCP socket API
  """
  def connect(dhost, port, options) do
    connect(dhost, port, options, @connect_timeout)
  end

  def connect(dhost, port, options, timeout) do
    host = if is_binary(dhost), do: :erlang.binary_to_list(dhost), else: dhost
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
        hostx = options[:connect_host]
        portx = options[:connect_port]
        options = List.keyreplace options, :connect_host, 0, {:connect_host, host}
        options = List.keyreplace options, :connect_port, 0, {:connect_port, port}
        case :gun_http_proxy.connect(hostx, portx, options, timeout) do
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
        :gen_tcp.connect(hostx, port, options, timeout)
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