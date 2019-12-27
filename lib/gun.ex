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
  def default_option(connect_timeout\\ 35000, recv_timeout\\ 20_000) do
    %{
      recv_timeout: recv_timeout,
      connect_timeout: connect_timeout,
      retry_timeout: 5000,
      retry: 0,
      transport_opts: [{:reuseaddr, true}, {:reuse_sessions, false}, {:linger, {false, 0}}, {:versions, [:"tlsv1.2"]}]
    }
  end

  def http_request(method, url, headers, body, opts, ref) do
    u = :gun_url.parse_url(url)
    conn = Process.get(ref)
    if is_pid(conn) and Process.alive?(conn) do
      mref = Process.monitor(conn)
      stream = :gun.request(conn, method, u.raw_path, headers, body, opts)
      case http_recv(conn, stream, ref, mref, Map.get(opts, :recv_timeout, 20000)) do
        {:error, :retry} ->
          http_await_make_request(conn, ref, mref, method, u.raw_path, headers, body, opts)
        resp ->
          resp
      end
    else
      opts =
        if u.scheme == :https, do: Map.merge(opts, %{transport: :tls}), else: opts
      case :gun.open(u.host, u.port, opts) do
        {:ok, conn} ->
          mref = Process.monitor(conn)
          Process.put(conn, u.raw_path)
          http_await_make_request(conn, ref, mref, method, u.raw_path, headers, body, opts)
        resp ->
          resp
      end
    end
  end

  def http_await_make_request(conn, ref, mref, method, raw_path, headers, body, opts) do
    case :gun.await_up(conn, Map.get(opts, :connect_timeout, 15000), mref) do
      {:ok, _protocols} ->
        if ref != nil, do: Process.put(ref, conn)
        stream = :gun.request(conn, method, raw_path, headers, body, opts)
        case http_recv(conn, stream, ref, mref, Map.get(opts, :recv_timeout, 10000)) do
          {:error, :retry} ->
            http_await_make_request(conn, ref, mref, method, raw_path, headers, body, opts)
          resp ->
            resp
        end
      {:error, reason} ->
        Process.demonitor(mref, [:flush])
        http_close(ref, conn)
        {:error, reason}
    end
  end

  def http_recv(conn, stream, ref, mref, timeout) do
    resp = http_recv(conn, stream, ref, mref, timeout, %{status_code: 200, headers: [], body: "", reason: nil})
    case resp do
      {:error, :retry} ->
        resp
      {:error, _} ->
        Process.demonitor(mref, [:flush])
        http_close(ref, conn)
        resp
      _ ->
        Process.demonitor(mref, [:flush])
        if ref == nil do
          http_close(ref, conn)
          resp
        else
          resp
        end
    end
  end

  defp http_format_error(reason) do
    case reason do
      :normal -> {:error, :closed}
      :close -> {:error, :closed}
      {:error, {:down, {:shutdown, error}}} -> {:error, error}
      {:error, _} -> reason
      _ -> {:error, reason}
    end
  end

  def http_recv(conn, stream, ref, mref, timeout, resp) do
    receive do
      {:gun_response, ^conn, ^stream, :fin, status, headers} ->
        Map.merge(resp, %{status_code: status, headers: headers})
      {:gun_response, ^conn, ^stream, :nofin, status, headers} ->
        http_recv(conn, stream, ref, mref, timeout, Map.merge(resp, %{status_code: status, headers: headers}))
      {:gun_data, ^conn, ^stream, :fin, data} ->
        data1 = resp.body <> data
        %{resp| body: data1}
      {:gun_data, ^conn, ^stream, :nofin, data} ->
        data1 = resp.body <> data
        http_recv(conn, stream, ref, mref, timeout, %{resp| body: data1})
      {:DOWN, ^mref, :process, ^conn, reason} ->
        {:error, reason}
      {:gun_down, ^conn, _proto, reason, retry, _killed_stream, _unprocessed_stream} ->
        if retry > 0 do
          {:error, :retry}
        else
          http_format_error(reason)
        end
      {:gun_error, ^conn, ^stream, reason} ->
        {:error, reason}
      {:gun_error, ^conn, reason} ->
        {:error, reason}
    after
      timeout ->
        {:error, :timeout}
    end
  end

  def http_close(ref, conn\\ nil) do
    conn1 = Process.delete(ref)
    conn2 = if is_pid(conn1), do: conn1, else: conn
    Process.delete(conn2)
    if is_pid(conn2) and Process.alive?(conn2) == true do
      :gun.shutdown(conn2)
      :gun.flush(conn2)
    end
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
      options[:remote_host] != nil ->
        # remote_host, remote_port, (remote_transport), remote_proxy == [proxy, proxy_auth, (socks5_resolve)]
        case :gun_remote_proxy.connect(host, port, options, timeout) do
          {:ok, {_, socket}} ->
            {:ok, socket}
          exp ->
            exp
        end
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