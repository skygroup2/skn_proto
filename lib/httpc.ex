defmodule HackneyEx do
  require Logger

  def decode_gzip(response) when is_map(response) do
    decode_gzip(response.headers, response.body)
  end

  def decode_gzip(headers, body) do
    h = :maps.from_list(headers)

    if h["Content-Encoding"] == "gzip" or h["content-encoding"] == "gzip" do
      :zlib.gunzip(body)
    else
      body
    end
  end

  def get_rest(:ignore) do
    %{}
  end

  def get_rest({:ok, response}) do
    case response.status_code do
      200 ->
        uz = decode_gzip(response)

        if uz == "" do
          %{}
        else
          Poison.decode!(uz)
        end

      _ ->
        throw({:error, response})
    end
  end

  def get_rest({:error, reason}) do
    throw({:error, reason})
  end

  def get_body({:ok, response}) do
    case response.status_code do
      200 ->
        uz = decode_gzip(response)

        if uz == "" do
          %{}
        else
          uz
        end

      _ ->
        throw({:error, response})
    end
  end

  def get_body({:error, reason}) do
    throw({:error, reason})
  end

  def send_rest(method, url, body, headers, opts, retry \\ 0, max_retry \\ 0) do
    ret = HTTPoison.request(method, url, body, headers, opts)

    case ret do
      {:error, _reason} ->
        if retry < max_retry do
          send_rest(method, url, body, headers, opts, retry + 1, max_retry)
        else
          ret
        end
      _ ->
        ret
    end
  end

  def close_rest2(cname \\ :hackney_client) do
    ref = Process.delete({cname, :ref})

    if is_reference(ref) do
      :hackney.close(ref)
    end

    ref
  end

  def send_rest2(method, url, body, headers, proxy_opts, cname \\ :hackney_client, retry \\ 0) do
    hackney_opts = proxy_opts[:hackney]
    ref = Process.get({cname, :ref}, nil)
    flag = Process.get({cname, :flag}, true)
    url1 = HackneyEx.parse_url(url)
    headers = if is_map(headers), do: Map.to_list(headers), else: headers

    {ref, flag} =
      case ref do
        nil ->
          #            Logger.debug "create new connection"
          case HackneyEx.connect(url1, hackney_opts) do
            {:ok, client_ref, flag} ->
              Process.put({cname, :ref}, client_ref)
              Process.put({cname, :flag}, flag)
              {client_ref, flag}

            {:error, reason}
            when reason == :closed or reason == :timeout or reason == :connect_timeout or
                   reason == :econnrefused or reason == :ehostunreach or reason == :proxy_error or
                   reason == :etimedout ->
              throw({:change_ip, {:error, reason}})

            {:error, reason} ->
              throw({:error, reason})
          end

        _ ->
          {ref, flag}
      end

    headers = :hackney_headers_new.new(headers)
    request = HackneyEx.make_request(method, url1, headers, body, hackney_opts, flag)

    case :hackney.send_request(ref, request) do
      {:ok, 200, rheaders, ref1} ->
        Process.put({cname, :ref}, ref1)

        case :hackney.body(ref1) do
          {:ok, body} ->
            decode_gzip(rheaders, body)

          {:error, :timeout} ->
            :hackney.close(ref)
            Process.put({cname, :ref}, nil)
            throw({:change_ip, {:error, :timeout}})

          {:error, reason} ->
            :hackney.close(ref)
            Process.put({cname, :ref}, nil)
            throw({:error, reason})
        end

      {:ok, code, _rheaders, ref1} ->
        {:ok, body} = :hackney.body(ref1)
        :hackney.close(ref1)
        Process.put({cname, :ref}, nil)
        {:error, code, body}

      {:error, reason} when reason == :closed ->
        :hackney.close(ref)
        Process.put({cname, :ref}, nil)

        if retry <= 0 do
          throw({:change_ip, {:error, reason}})
        else
          send_rest2(method, url, body, headers, proxy_opts, cname, retry - 1)
        end

      {:error, reason} ->
        :hackney.close(ref)
        Process.put({cname, :ref}, nil)
        throw({:error, reason})
    end
  end

  #    def update_ifs() do
  #        x = case :inet.getifaddrs() do
  #        {:ok, ifs} ->
  #            ips = Enum.reduce ifs, [], fn ({i, l}, acc) ->
  #                if i != 'lo' do
  #                    Enum.reduce l, acc, fn({k, v}, acc0) ->
  #                        if k == :addr do
  #                            case V1.Util.check_ipv4(v) do
  #                            {true, :public} ->
  #                                [v| acc0]
  #                            _ ->
  #                                acc0
  #                            end
  #                        else
  #                            acc0
  #                        end
  #                    end
  #                else
  #                    acc
  #                end
  #            end
  #            ips
  #        _ ->
  #            []
  #        end
  #        V1.DB.Config.set :ips, x
  #        x
  #    end
  #
  #    def get_if() do
  #        i = V1.DB.Counter.update_counter(:if_seq, 1)
  #        ips = V1.DB.Config.get :ips, []
  #        if ips == [] do
  #            []
  #        else
  #            ix = rem(i, length(ips))
  #            [{:connect_options, [{:ip, Enum.at(ips, ix)}]}]
  #        end
  #    end

  def ipify_me(proxy_opts, url \\ "http://lumtest.com/myip") do
    host = "lumtest.com"

    headers = %{
      Host: host,
      Connection: "Closed"
    }

    default_opts = [
      {:linger, {false, 0}},
      {:pool, false},
      {:recv_timeout, 30000},
      {:connect_timeout, 30000}
    ]

    proxy_opts = if length(proxy_opts) == 0, do: [hackney: default_opts], else: proxy_opts
    proxy_opts = Keyword.drop(proxy_opts[:hackney], [:ssl_options])
    proxy_opts = [{:hackney, proxy_opts}]

    try do
      case send_rest(:get, url, "", headers, proxy_opts, 0, 0) do
        {:ok, r} ->
          if r.status_code == 200 do
            decode_gzip(r)
          else
            nil
          end

        _ ->
          nil
      end
    catch
      _, _ ->
        nil
    end
  end

  def connect(%{transport: transport, host: host, port: port}, options) do
    case maybe_proxy(transport, host, port, options) do
      {:ok, ref, true} ->
        {:ok, ref, true}

      {:ok, ref} ->
        {:ok, ref, false}

      error ->
        error
    end
  end

  def maybe_proxy(transport, host, port, options)
      when is_list(host) and is_integer(port) and is_list(options) do
    case :proplists.get_value(:proxy, options) do
      url when is_binary(url) or is_list(url) ->
        #            ?report_debug("HTTP proxy request", [{url, Url}]),
        url1 = parse_url(url)
        %{transport: ptransport, host: proxyhost, port: proxyport} = normalize(url1)
        proxyauth = :proplists.get_value(:proxy_auth, options)

        case {transport, ptransport} do
          {:hackney_ssl, :hackney_ssl} ->
            {:error, :invalid_proxy_transport}

          {:hackney_ssl, _} ->
            do_connect(proxyhost, proxyport, proxyauth, transport, host, port, options)

          _ ->
            case :hackney_connect.connect(transport, proxyhost, proxyport, options, false) do
              {ok, ref} -> {ok, ref, true}
              error -> error
            end
        end

      {proxyhost, proxyport} ->
        #            ?report_debug("HTTP proxy request", [{proxy_host, ProxyHost}, {proxy_port, ProxyPort}]),
        case transport do
          :hackney_ssl ->
            proxyauth = :proplists.get_value(:proxy_auth, options)
            do_connect(proxyhost, proxyport, proxyauth, transport, host, port, options)

          _ ->
            case :hackney_connect.connect(transport, proxyhost, proxyport, options, false) do
              {ok, ref} -> {ok, ref, true}
              error -> error
            end
        end

      {:connect, proxyhost, proxyport} ->
        #            ?report_debug("HTTP tunnel request", [{proxy_host, ProxyHost}, {proxy_port, ProxyPort}]),
        proxyauth = :proplists.get_value(:proxy_auth, options)
        do_connect(proxyhost, proxyport, proxyauth, transport, host, port, options)

      {:socks5, proxyhost, proxyport} ->
        #            ?report_debug("SOCKS proxy request", [{proxy_host, ProxyHost}, {proxy_port, ProxyPort}]),
        proxyuser = :proplists.get_value(:socks5_user, options)
        proxypass = :proplists.get_value(:socks5_pass, options)
        proxyresolve = :proplists.get_value(:socks5_resolve, options)
        connectopts0 = :proplists.get_value(:connect_options, options, [])

        connectopts1 = [
          {:socks5_host, proxyhost},
          {:socks5_port, proxyport},
          {:socks5_user, proxyuser},
          {:socks5_pass, proxypass},
          {:socks5_resolve, proxyresolve},
          {:socks5_transport, transport} | connectopts0
        ]

        insecure = :proplists.get_value(:insecure, options, false)

        connectopts2 =
          case :proplists.get_value(:ssl_options, options) do
            :undefined ->
              [{:insecure, insecure}] ++ connectopts1

            sslopts ->
              [{:ssl_options, sslopts}, {:insecure, insecure}] ++ connectopts1
          end

        options1 = :lists.keystore(:connect_options, 1, options, {:connect_options, connectopts2})
        :hackney_connect.connect(:hackney_socks5, host, port, options1, false)

      _ ->
        #            ?report_debug("request without proxy", [])
        :hackney_connect.connect(transport, host, port, options, false)
    end
  end

  def do_connect(proxyhost, proxyport, :undefined, transport, host, port, options) do
    do_connect(proxyhost, proxyport, {:undefined, <<>>}, transport, host, port, options)
  end

  def do_connect(proxyhost, proxyport, {proxyuser, proxypass}, transport, host, port, options) do
    connectopts = :proplists.get_value(:connect_options, options, [])

    connectopts1 = [
      {:connect_host, host},
      {:connect_port, port},
      {:connect_transport, transport},
      {:connect_user, proxyuser},
      {:connect_pass, proxypass} | connectopts
    ]

    insecure = :proplists.get_value(:insecure, options, false)

    connectopts2 =
      case :proplists.get_value(:ssl_options, options) do
        :undefined ->
          [{insecure, insecure}] ++ connectopts1

        sslopts ->
          [{:ssl_options, sslopts}, {:insecure, insecure}] ++ connectopts1
      end

    options1 = :lists.keystore(:connect_options, 1, options, {:connect_options, connectopts2})
    :hackney_connect.connect(:hackney_http_connect, proxyhost, proxyport, options1, false)
  end

  defp host_header(%{transport: transport, netloc: netloc}, headers) do
    {_, headers1} =
      :hackney_headers_new.store_new(<<"Host">>, host_header_encode(transport, netloc), headers)

    headers1
  end

  defp host_header_encode(:hackney_local_tcp, netloc) do
    :hackney_url.urlencode(netloc)
  end

  defp host_header_encode(_transport, netloc) do
    netloc
  end

  def unparse_url(url) do
    u =
      {:hackney_url, url[:transport], url[:scheme], url[:netloc], url[:raw_path],
       Map.get(url, :path, ""), Map.get(url, :qs, ""), Map.get(url, :fragment, ""), url[:host],
       url[:port], Map.get(url, :user, ""), Map.get(url, :password, "")}

    :hackney_url.unparse_url(u)
  end

  def parse_url(url) do
    {:hackney_url, transport, scheme, netloc, raw_path, path, qs, fragment, host, port, user,
     password} = :hackney_url.parse_url(url)

    %{
      transport: transport,
      scheme: scheme,
      netloc: netloc,
      raw_path: raw_path,
      path: path,
      qs: qs,
      fragment: fragment,
      host: host,
      port: port,
      user: user,
      password: password
    }
  end

  def normalize(url) do
    u =
      {:hackney_url, url[:transport], url[:scheme], url[:netloc], url[:raw_path],
       Map.get(url, :path, ""), Map.get(url, :qs, ""), Map.get(url, :fragment, ""), url[:host],
       url[:port], Map.get(url, :user, ""), Map.get(url, :password, "")}

    {:hackney_url, transport, scheme, netloc, raw_path, path, qs, fragment, host, port, user,
     password} = :hackney_url.normalize(u)

    %{
      transport: transport,
      scheme: scheme,
      netloc: netloc,
      raw_path: raw_path,
      path: path,
      qs: qs,
      fragment: fragment,
      host: host,
      port: port,
      user: user,
      password: password
    }
  end

  def normalize(url, opts) do
    u =
      {:hackney_url, url[:transport], url[:scheme], url[:netloc], url[:raw_path],
       Map.get(url, :path, ""), Map.get(url, :qs, ""), Map.get(url, :fragment, ""), url[:host],
       url[:port], Map.get(url, :user, ""), Map.get(url, :password, "")}

    pathencodefun =
      :proplists.get_value(:path_encode_fun, opts, fn x -> :hackney_url.pathencode(x) end)

    {:hackney_url, transport, scheme, netloc, raw_path, path, qs, fragment, host, port, user,
     password} = :hackney_url.normalize(u, pathencodefun)

    %{
      transport: transport,
      scheme: scheme,
      netloc: netloc,
      raw_path: raw_path,
      path: path,
      qs: qs,
      fragment: fragment,
      host: host,
      port: port,
      user: user,
      password: password
    }
  end

  def make_request(:connect, %{} = url, headers, body, _, _) do
    %{host: host, port: port} = url
    headers1 = host_header(url, headers)
    path = :erlang.iolist_to_binary([host, ":", :erlang.integer_to_list(port)])
    {:connect, path, headers1, body}
  end

  def make_request(method, %{} = url, headers0, body, options, true) do
    headers1 = host_header(url, headers0)
    finalpath = unparse_url(url)

    headers =
      case :proplists.get_value(:proxy_auth, options) do
        :undefined ->
          headers1

        {user, pwd} ->
          credentials = :base64.encode(user <> ":" <> pwd)
          :hackney_headers_new.store("proxy-authorization", "basic " <> credentials, headers1)
      end

    {method, finalpath, headers, body}
  end

  def make_request(method, %{} = url, headers, body, _, _) do
    %{path: path, qs: query} = url
    headers1 = host_header(url, headers)

    finalpath =
      case query do
        <<>> -> path
        _ -> path <> "?" <> query
      end

    {method, finalpath, headers1, body}
  end
end
