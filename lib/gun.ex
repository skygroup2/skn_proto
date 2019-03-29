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
        + {:remote, {127, 0, 0, 1}, 22222}
      - proxy_auth: {u, p}
      - remote_proxy: [] | #{}
        + proxy: same
        + proxy_auth: same
        + proxy_ip: {127, 0, 0, 1}
        + timeout : non_neg_integer
        + type: socks5 | http
        + socks5_resolve : same ( in case socks5)
      - socks5_resolve: :local | :remote ( in case socks5)
      - protocols: [:http| :http2]
      - transport: tcp | tls
      - transport_opts  => [gen_tcp:connect_option()] | [ssl:connect_option()]
      - http_opts => #{}
      - http2_opts => #{}
      - ws_opts => #{}
  """
  def http_request(method, url, headers, body, opts, ref) do
    u = :gun_url.parse_url(url)
    conn = Process.get(ref)
    if is_pid(conn) and Process.alive?(conn) do
      stream = :gun.request(conn, method, u.path, headers, body, opts)
      http_recv(conn, stream, ref, Map.get(opts, :recv_timeout, 10000))
    else
      opts =
        if u.scheme == :https, do: Map.merge(opts, %{transport: :tls}), else: opts
      case :gun.open(u.host, u.port, opts) do
        {:ok, conn} ->
#          IO.inspect "#{method} #{url} => #{inspect conn}"
          case :gun.await_up(conn, Map.get(opts, :connect_timeout, 15000)) do
            {:ok, _protocols} ->
              if ref != nil, do: Process.put(ref, conn)
              stream = :gun.request(conn, method, u.raw_path, headers, body, opts)
              http_recv(conn, stream, ref, Map.get(opts, :recv_timeout, 10000))
            {:error, reason} ->
              :gun.shutdown(conn)
              {:error, reason}
          end
        exp ->
          exp
      end
    end
  end

  def http_recv(conn, stream, ref, timeout\\ 5000) do
    mref = Process.monitor(conn)
    resp = http_recv(conn, stream, mref, ref, timeout, %{status_code: 200, headers: [], body: "", reason: nil})
    Process.demonitor(mref, [:flush])
    case resp do
      _ when ref == nil ->
        :gun.close(conn)
        :gun.flush(conn)
        resp
      {:error, _} ->
        http_close(ref)
        resp
      _ ->
        resp
    end
  end

  def http_recv(conn, stream, mref, ref, timeout, resp) do
    receive do
      {:gun_response, ^conn, ^stream, :fin, status, headers} ->
        Map.merge(resp, %{status_code: status, headers: headers})
      {:gun_response, ^conn, ^stream, :nofin, status, headers} ->
        http_recv(conn, stream, mref, ref, timeout, Map.merge(resp, %{status_code: status, headers: headers}))
      {:gun_data, ^conn, ^stream, :fin, data} ->
        data1 = resp.body <> data
        %{resp| body: data1}
      {:gun_data, ^conn, ^stream, :nofin, data} ->
        data1 = resp.body <> data
        http_recv(conn, stream, mref, ref, timeout, %{resp| body: data1})
      {:DOWN, ^mref, :process, ^conn, reason} ->
        {:error, reason}
      {:gun_error, ^conn, ^stream, reason} ->
        {:error, reason}
      {:gun_error, ^conn, reason} ->
        {:error, reason}
    after
      timeout ->
        {:error, :timeout}
    end
  end

  def http_close(ref) do
    conn = Process.delete(ref)
    if is_pid(conn) and Process.alive?(conn) do
      :gun.close(conn)
    end
  end

  def decode_gzip(response) do
    decode_gzip(response.headers, response.body)
  end

  def decode_gzip(headers, body) do
    case List.keyfind(headers, "content-encoding", 0) do
      {"content-encoding", "gzip"} ->
        :zlib.gunzip(body)
      {"content-encoding", _} ->
        body
      nil ->
        body
    end
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
    host = if is_binary(dhost), do: :erlang.binary_to_list(dhost), else: dhost
    cond do
      options[:remote_host] != nil ->
        # remote_host, remote_port, (remote_transport), remote_proxy == [proxy, proxy_auth, (socks5_resolve)]
        case :gun_remote_proxy.connect(host, port, options, @connect_timeout) do
          {:ok, {_, socket}} ->
            {:ok, socket}
          exp ->
            exp
        end
      options[:socks5_host] != nil ->
        # socks5_host, socks5_port, (socks5_transport), socks5_user, socks5_pass, (socks5_resolve)
        case :gun_socks5_proxy.connect(host, port, options, @connect_timeout) do
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
        case :gun_http_proxy.connect(hostx, portx, options, @connect_timeout) do
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