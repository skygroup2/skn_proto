defmodule HttpEx do
  @moduledoc """
    extend gun for cookie supported
  """
  require Logger
  require Skn.Log

  defp check_add_proxy(proxy, default_opts) do
    proxy_strict = Process.get(:proxy_strict, false)
    case proxy do
      :skip ->
        default_opts
      nil ->
        if proxy_strict == false, do: default_opts, else: raise "NO_PROXY"
      %{proxy: nil} ->
        if proxy_strict == false, do: default_opts, else: raise "NO_PROXY"
      %{type: ip6_type, ip: ip6} when ip6_type in [:ip6, :ip6_v1, :ip6_v2] ->
        tcp_opts = if is_tuple(ip6) do
          [:inet6, {:ip, ip6}, :binary, {:reuseaddr, true}, {:keepalive, false}, {:nodelay, false}, {:active, true}, {:linger, {true, 0}}]
        else
          [:inet6, :binary, {:reuseaddr, true}, {:keepalive, false}, {:nodelay, false}, {:active, true}, {:linger, {true, 0}}]
        end
        Map.merge(default_opts, %{tcp_opts: tcp_opts})
      %{type: :ip4, ip: ip4} ->
        tcp_opts = if is_tuple(ip4) do
          [:inet, {:ip, ip4}, :binary, {:reuseaddr, true}, {:keepalive, false}, {:nodelay, false}, {:active, true}, {:linger, {true, 0}}]
        else
          [:inet, :binary, {:reuseaddr, true}, {:keepalive, false}, {:nodelay, false}, {:active, true}, {:linger, {true, 0}}]
        end
        Map.merge(default_opts, %{tcp_opts: tcp_opts})
      _ ->
        Map.merge(default_opts, %{proxy: proxy[:proxy], proxy_auth: proxy[:proxy_auth], socks5_resolve: :remote})
    end
  end

  def proxy_option(proxy, opts) do
    new_opts = Map.merge(Gun.default_option(25_000, 90_000), opts)
    |> Map.merge(%{http2_opts: %{settings_timeout: 25_000, preface_timeout: 25_000},
      tls_opts: [{:reuse_sessions, true}, {:verify, :verify_none}, {:logging_level, :error}, {:log_alert, false}],
#      protocols: [:http]
    })
    check_add_proxy(proxy, new_opts)
  end
  def ws_proxy_option(proxy, opts) do
    new_opts = Map.merge(Gun.ws_default_option(25_000, 60_000), opts)
    check_add_proxy(proxy, new_opts)
  end

# Cookies API
  @type cookie_option() :: {binary(), binary()}
  @type cookie_opts() :: [cookie_option()]

  @spec format_cookie(cookie_opts(), binary()) :: binary()
  def format_cookie(cookies, str) do
    Enum.reduce(cookies, str, fn {k, v}, acc ->
      d = if acc == "", do: "", else: "; "
      if is_binary(v) do
        acc <> d <> "#{k}=#{v}"
      else
        acc <> d <> "#{k}"
      end
    end)
  end

  @spec parse_cookie(binary()) :: [{binary(), binary()}] | {:error, :badarg}
  def parse_cookie(cookie), do: parse_cookie(cookie, [])
  def parse_cookie(<<>>, acc), do: Enum.reverse(acc)
  def parse_cookie(<< ?\s, rest :: binary >>, acc), do: parse_cookie(rest, acc)
  def parse_cookie(<< ?\t, rest :: binary >>, acc), do: parse_cookie(rest, acc)
  def parse_cookie(<< ?,, rest :: binary >>, acc), do: parse_cookie(rest, acc)
  def parse_cookie(<< ?;, rest :: binary >>, acc), do: parse_cookie(rest, acc)
  def parse_cookie(<< ?$, rest :: binary >>, acc), do: skip_cookie(rest, acc)
  def parse_cookie(cookie, acc), do: parse_cookie_name(cookie, acc, <<>>)

  def skip_cookie(<<>>, acc), do: Enum.reverse(acc)
  def skip_cookie(<< ?,, rest :: binary >>, acc), do: parse_cookie(rest, acc)
  def skip_cookie(<< ?;, rest :: binary >>, acc), do: parse_cookie(rest, acc)
  def skip_cookie(<< _, rest :: binary >>, acc), do: skip_cookie(rest, acc)

  def parse_cookie_name(<<>>, acc, name) when name != "", do: Enum.reverse([{name, true} | acc])
  def parse_cookie_name(<<>>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< ?=, _ :: binary >>, _, <<>>), do: {:error, :badarg}
  def parse_cookie_name(<< ?=, rest :: binary >>, acc, name), do: parse_cookie_value(rest, acc, name, "")
  def parse_cookie_name(<< ?,, _ :: binary >>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< ?;, rest :: binary >>, acc, name), do: parse_cookie(rest, [{name, true} | acc])
  def parse_cookie_name(<< ?\s, _ :: binary >>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< ?\t, _ :: binary >>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< ?\r, _ :: binary >>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< ?\n, _ :: binary >>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< ?\v, _ :: binary >>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< ?\f, _ :: binary >>, _, _), do: {:error, :badarg}
  def parse_cookie_name(<< c, rest :: binary >>, acc, name), do: parse_cookie_name(rest, acc, << name :: binary, c >>)

  def parse_cookie_value(<<>>, acc, name, value), do: Enum.reverse([{name, parse_cookie_trim(value)}|acc])
  def parse_cookie_value(<< ?;, rest :: binary >>, acc, name, value), do: parse_cookie(rest, [{name, parse_cookie_trim(value)}|acc])
  def parse_cookie_value(<< ?\t, _ :: binary >>, _, _, _), do: {:error, :badarg}
  def parse_cookie_value(<< ?\r, _ :: binary >>, _, _, _), do: {:error, :badarg}
  def parse_cookie_value(<< ?\n, _ :: binary >>, _, _, _), do: {:error, :badarg}
  def parse_cookie_value(<< ?\v, _ :: binary >>, _, _, _), do: {:error, :badarg}
  def parse_cookie_value(<< ?\f, _ :: binary >>, _, _, _), do: {:error, :badarg}
  def parse_cookie_value(<< c, rest :: binary >>, acc, name, value), do: parse_cookie_value(rest, acc, name, << value :: binary, c >>)

  def parse_cookie_trim(""), do: ""
  def parse_cookie_trim(value) do
    case :binary.last(value) do
      ?\s ->
        size = byte_size(value) - 1
        << value2 :: binary-size(size), _ >> = value
        parse_cookie_trim(value2)
      _ ->
        value
    end
  end

  def get_redirect_url(origin_uri, location) do
    case URI.parse(location) do
      %URI{host: host} when host != nil ->
        location
      _ ->
        "#{origin_uri.scheme}://#{origin_uri.host}#{location}"
    end
  end

  def match_cookie?(v, uri) do
    String.contains?(uri.host, v.domain) and String.contains?(uri.path || "/", v.path)
  end

  def get_cookie(all_cookies, uri) do
    ts_now = System.system_time(:millisecond)
    Enum.filter(all_cookies, fn {_, v} ->
      v.expires > ts_now and match_cookie?(v, uri)
    end)
  end

  def save_cookie(all_cookies, [{name, value}|_] = cookies, uri) do
    max_age = case List.keyfind(cookies, "Max-Age", 0) || List.keyfind(cookies, "max-age", 0) do
      {_, v} -> String.to_integer(v)
      nil -> nil
    end
    expires = case List.keyfind(cookies, "Expires", 0) || List.keyfind(cookies, "expires", 0) do
      {_, v} -> ((:gun_http_date.parse_http_date(v) |> :calendar.datetime_to_gregorian_seconds()) - 62167219200) * 1000
      nil -> nil
    end
    ts_now = System.system_time(:millisecond)
    all_cookies = Enum.filter(all_cookies, fn {_, x} -> x.expires > ts_now end)
    store_cookies = [{name, value}]
    if max_age > 0 do
      {_, path} = List.keyfind(cookies, "Path", 0) || List.keyfind(cookies, "path", 0, {"Path", "/"})
      {_, domain} = List.keyfind(cookies, "Domain", 0) || List.keyfind(cookies, "domain", 0, {"Domain", uri.host})
      List.keystore(all_cookies, name, 0, {name, %{domain: domain, path: path, expires: expires, value: store_cookies}})
    else
      List.keydelete(all_cookies, name, 0)
    end
  end

  def save_cookie_from_header(all_cookies, headers, uri) do
    Enum.reduce(headers, all_cookies, fn {k, v}, acc ->
      if k == "set-cookie" do
        c = parse_cookie(v)
        save_cookie(acc, c, uri)
      else
        acc
      end
    end)
  end

  def set_cookie(headers, all_cookie, uri) do
    cookies = get_cookie(all_cookie, uri)
    if cookies != [] do
      v = Enum.reduce(cookies, "", fn {_, x}, acc -> format_cookie(x.value, acc) end)
      Map.put(headers, "cookie", v)
    else
      headers
    end
  end

  # cookies = [{name, %{domain: "", path: "", value: [{k, v}]}}]
  def request(bot_id, method, url, headers, body, opt, redirect, all_cookies, conn_ref) do
    request(bot_id, method, url, headers, body, opt, redirect, all_cookies, conn_ref, 1, &resolve_host/1)
  end
  def request(bot_id, method, url, headers, body, opt, redirect, all_cookies, conn_ref, retry, resolve_fun) do
#    Skn.Log.debug("bot #{bot_id} #{method}: #{url}")
    uri = URI.parse(url)
    headers = set_cookie(headers, all_cookies, uri)
    resp = Gun.http_request(method, url, headers, body, opt, conn_ref, resolve_fun)
    case resp do
      {:error, reason} when reason in [:closed, :timeout] and retry > 0 ->
        # retry on error closed
        Gun.http_close(conn_ref, nil)
        request(bot_id, method, url, headers, body, opt, redirect, all_cookies, conn_ref, retry - 1, resolve_fun)
      %{status_code: 302, headers: resp_headers} when redirect > 0 ->
        {_, location} = List.keyfind(resp_headers, "location", 0)
        redirect_url = get_redirect_url(uri, location)
        new_cookie = save_cookie_from_header(all_cookies, resp_headers, uri)
        Skn.Log.debug("bot #{bot_id} redirect #{redirect_url}")
        request(bot_id, "GET", redirect_url, headers, "", opt, redirect - 1, new_cookie, nil, 1, resolve_fun)
      %{status_code: status_code, body: body, headers: resp_headers} ->
        if status_code >= 400, do: Gun.http_close(conn_ref, nil)
        resp_body = decompress_data(body, :proplists.get_all_values("content-encoding", resp_headers))
        new_cookie = save_cookie_from_header(all_cookies, resp_headers, uri)
        {_, location} = List.keyfind(resp_headers, "location", 0, {"location", nil})
        Map.merge(%{resp| body: resp_body}, %{cookies: new_cookie, origin_url: url, redirect_url: location, code: nil})
      _ ->
        resp
    end
  end

  defp decompress_data(data, algorithms) do
    Enum.reduce(List.wrap(algorithms), data, &decompress_with_algorithm/2)
  end

  defp decompress_with_algorithm(gzip, data) when gzip in ["gzip", "x-gzip"], do: :zlib.gunzip(data)
  defp decompress_with_algorithm("deflate", data), do: :zlib.unzip(data)
  defp decompress_with_algorithm("identity", data), do: data
  defp decompress_with_algorithm(algorithm, _data), do: raise "unsupported algorithm: #{inspect(algorithm)}"

  def resolve_host(host) do
    to_charlist(host)
  end
end
