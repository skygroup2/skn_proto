-module(gen_tcp_acceptor).
-compile([{parse_transform, lager_transform}]).

-export([start_link/1,
  new_acceptor/1,
  acceptor_slave_init/4
]).

-define(ACCEPTOR_TIMEOUT, 1000).

start_link(Args) ->
  proc_lib:start_link(?MODULE, new_acceptor, [erlang:append_element(Args, self())]).

new_acceptor({Sup, Ips, Port, Opts, Parent}) when Port > 0 andalso Port < 65536 ->
  IpAddrs = reformat_ip(Ips, []),
  process_flag(trap_exit, true),
  N = get_opt(n_acceptor, Opts, 2),
  if
    length(IpAddrs) > 0 ->
      case gen_tcp:listen(Port, [binary, {reuseaddr, true}, {active, false}] ++ [{ip, X} || X <- IpAddrs]) of
        {ok, LSocket} ->
          Slaves = acceptor_slave_spawn(N, LSocket, Sup, Opts, []),
          proc_lib:init_ack(Parent, {ok, self()}),
          acceptor_master(LSocket, Slaves);
        {error, Reason} ->
          lager:error("bind on port ~p is failed: ~p", [Port, Reason]),
          proc_lib:init_ack(Parent, {error, Reason})
      end;
    true ->
      proc_lib:init_ack(Parent, {error, einval})
  end.


acceptor_master(LSocket, Slaves) ->
  receive
    {socket_closed, LSocket, Slv1} ->
      Slvs = lists:delete(Slv1, Slaves),
      [X ! {stop, self()} || X <- Slvs],
      acceptor_master_wait(Slvs);

    _ ->
      ok
  end.


acceptor_master_wait(Slvs) ->
  lager:debug("wait for ~p died", [Slvs]),
  receive
    {'EXIT', Slv1, _} ->
      NSlvs = lists:delete(Slv1, Slvs),
      if
        length(NSlvs) == 0 ->
          exit(normal);
        true ->
          acceptor_master_wait(NSlvs)
      end;
    Msg ->
      lager:warning("drop unknown message ~p", [Msg]),
      acceptor_master_wait(Slvs)
  after 3000 ->
    lager:warning("wait for slave too long, force exiting"),
    exit(normal)
  end.

acceptor_slave_spawn(1, LSocket, Sup, Opts, In) ->
  Pid = spawn_link(?MODULE, acceptor_slave_init, [self(), LSocket, Sup, Opts]),
  [Pid | In];

acceptor_slave_spawn(N, LSocket, Sup, Opts, In) ->
  Pid = spawn_link(?MODULE, acceptor_slave_init, [self(), LSocket, Sup, Opts]),
  acceptor_slave_spawn(N - 1, LSocket, Sup, Opts, [Pid | In]).


acceptor_slave_init(Master, LSocket, Sup, Opts) ->
  process_flag(trap_exit, true),
  acceptor_slave(Master, LSocket, Sup, Opts).

acceptor_slave(Master, LSocket, Sup, Opts) ->
  case gen_tcp:accept(LSocket, ?ACCEPTOR_TIMEOUT) of
    {ok, Socket} ->
      lager:debug("new socket connected from ~p", [peer_info(Socket)]),
      case Sup:add_socket(Socket, Opts) of
        {ok, Pid} ->
          lager:debug("~p create new controller ~p <-> ~p", [self(), Pid, Socket]),
          gen_tcp:controlling_process(Socket, Pid);
        _ ->
          lager:error("can not create new controller => close new socket"),
          gen_tcp:close(Socket)
      end,
      acceptor_slave_check(Master, LSocket, Sup, Opts);
    {error, timeout} ->
      acceptor_slave_check(Master, LSocket, Sup, Opts);
    {error, system_limit} ->
      lager:notice("file descriptor reach to limit"),
      acceptor_slave_check(Master, LSocket, Sup, Opts);
    {error, closed} ->
      Master ! {socket_closed, LSocket, self()},
      exit(normal);
    {error, Posix} ->
      lager:error("error on socket ~p", [inet:format_error(Posix)]),
      acceptor_slave_check(Master, LSocket, Sup, Opts)
  end.

acceptor_slave_check(Master, LSocket, Sup, Opts) ->
  receive
    {stop, Master} ->
      %% stop command from master
      exit(normal);
    {'EXIT', Master, _} ->
      %% master process die
      exit(normal);
    Msg ->
      lager:warning("drop unknown message ~p", [Msg]),
      acceptor_slave(Master, LSocket, Sup, Opts)
  after 0 ->
    acceptor_slave(Master, LSocket, Sup, Opts)
  end.


reformat_ip([A | _] = SingleIp, In) when not is_list(A) ->
  case inet:parse_ipv4_address(SingleIp) of
    {ok, Ipv4} ->
      [Ipv4 | In];
    _ ->
      lager:error("Invalid IPv4 address ~p", [SingleIp]),
      In
  end;

reformat_ip(SingleIp, In) when is_tuple(SingleIp), size(SingleIp) == 4 ->
  try
    {ok, SingleIp} = inet:parse_ipv4_address(inet:ntoa(SingleIp)),
    [SingleIp | In]
  catch
    _:_ ->
      lager:error("Invalid IPv4 address ~p", [SingleIp]),
      In
  end;

reformat_ip([SingleIp | Rem], In) ->
  In1 = case inet:parse_ipv4_address(SingleIp) of
          {ok, Ipv4} -> [Ipv4 | In];
          _ ->
            lager:error("Invalid IPv4 address ~p", [SingleIp]),
            In
        end,
  reformat_ip(Rem, In1).

peer_info(Socket) ->
  case inet:peername(Socket) of
    {ok, {Address, Port}} ->
      lists:flatten(io_lib:format("~p:~p", [inet:ntoa(Address), Port]));
    {error, Posix} ->
      inet:format_error(Posix)
  end.

get_opt(K, Opts, Default) ->
  case lists:keyfind(K, 1, Opts) of
    false ->
      Default;
    {K, V} ->
      V
  end.