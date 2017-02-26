-module(quic_connection).
-behaviour(gen_server).
-behaviour(quic_stream_handler).

-include("quic.hrl").
-include("quic_data_kv.hrl").
-include("quic_frame.hrl").
-include("quic_packet.hrl").
-include("quic_numeric.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/4]). -ignore_xref({start_link,4}).
-export([dispatch_packet/2]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% ------------------------------------------------------------------
%% quic_stream_handler Function Exports (for crypto)
%% ------------------------------------------------------------------

-export([start_stream/2]).
-export([handle_inbound/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

-define(CRYPTO_STREAM_ID, 1).
-define(DEFAULT_PING_INTERVAL, 5).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          component_supervisor_pid :: pid(),
          controlling_pid :: pid(),
          controlling_pid_monitor :: reference(),
          remote_hostname :: inet:hostname(),
          remote_ip_address :: inet:ip_address(),
          remote_port :: inet:port_number(),
          remote_sni :: iodata(),
          socket :: inet:socket(),
          crypto_state :: quic_crypto:state(),
          inflow_pid :: pid(),
          inflow_monitor :: reference(),
          outflow_pid :: pid(),
          outflow_monitor :: reference(),
          ping_timer :: undefined | reference(),
          ping_interval :: non_neg_integer() % in seconds
         }).
-type state() :: #state{}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(ComponentSupervisorPid, ControllingPid, RemoteHostname, RemotePort) ->
    gen_server:start_link(
      ?CB_MODULE,
      [ComponentSupervisorPid, ControllingPid,
       RemoteHostname, RemotePort], []).

-spec dispatch_packet(pid(), quic_packet()) -> ok.
dispatch_packet(ConnectionPid, Packet) ->
    gen_server:cast(ConnectionPid, {dispatch_packet, Packet}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([ComponentSupervisorPid, ControllingPid, RemoteHostname, RemotePort]) ->
    UdpOpts = [{active, 10},
               {mode, binary}],
    {ok, Socket} = gen_udp:open(0, UdpOpts),
    gen_server:cast(self(), maybe_setup_connection),
    {ok, #state{
            component_supervisor_pid = ComponentSupervisorPid,
            controlling_pid = ControllingPid,
            controlling_pid_monitor = monitor(process, ControllingPid),
            remote_hostname = RemoteHostname,
            remote_port = RemotePort,
            socket = Socket }}.

handle_call(Request, From, State) ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast(maybe_setup_connection, State) ->
    maybe_setup_connection(State);
handle_cast({dispatch_packet, QuicPacket}, State) ->
    send_packet(QuicPacket, State),
    {noreply, State};
handle_cast({start_quic_crypto_stream, StreamPid}, #state{ crypto_state = CryptoState } = State) ->
    NewCryptoState = quic_crypto:start_stream(StreamPid, CryptoState),
    {noreply, State#state{ crypto_state = NewCryptoState }};
handle_cast({crypto_stream_inbound, DataKv}, #state{ crypto_state = CryptoState } = State) ->
    NewCryptoState = quic_crypto:handle_stream_inbound(DataKv, CryptoState),
    {noreply, State#state{ crypto_state = NewCryptoState }};
handle_cast(Msg, State) ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

handle_info({udp_passive, Socket}, #state{ socket = Socket } = State) ->
    ok = inet:setopts(Socket, [{active, once}]),
    {noreply, State};
handle_info({udp, Socket, _SenderIp, _SenderPort, Data}, #state{ socket = Socket } = State) ->
    NewState = handle_received_data(Data, State),
    {noreply, NewState};
handle_info({'DOWN', Reference, process, _Pid, _Reason}, State)
  when Reference =:= State#state.controlling_pid_monitor ->
    {stop, oops, State};
handle_info({'DOWN', Reference, process, _Pid, Reason}, State)
  when Reference =:= State#state.inflow_monitor  ->
    {stop, {shutdown, Reason}, State};
handle_info({'DOWN', Reference, process, _Pid, Reason}, State)
  when Reference =:= State#state.outflow_monitor  ->
    {stop, {shutdown, Reason}, State};
handle_info(send_ping, State) ->
    quic_outflow:dispatch_frame(State#state.outflow_pid, #ping_frame{}),
    NewPingTimer = erlang:send_after(
                     timer:seconds(State#state.ping_interval),
                     self(), send_ping),
    {noreply, State#state{ ping_timer = NewPingTimer }};
handle_info(Info, State) ->
    lager:debug("unhandled info ~p on state ~p", [Info, State]),
    {noreply, State}.

terminate({shutdown, Reason}, _State) ->
    lager:debug("shutting down: ~p", [Reason]),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% quic_stream Function Definitions (for crypto)
%% ------------------------------------------------------------------

start_stream(HandlerPid, StreamPid) ->
    gen_server:cast(HandlerPid, {start_quic_crypto_stream, StreamPid}),
    {ok, data_kv}.

handle_inbound(HandlerPid, DataKvs) ->
    lists:foreach(
      fun (DataKv) ->
              gen_server:cast(HandlerPid, {crypto_stream_inbound, DataKv})
      end,
      DataKvs).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_packet(quic_packet(), state()) -> ok.
send_packet(QuicPacket, State) ->
    #state{ remote_ip_address = RemoteIpAddress,
            remote_port = RemotePort,
            socket = Socket } = State,

    CryptoState = outbound_packet_crypto_state(QuicPacket, State#state.crypto_state),
    Data = quic_packet:encode(QuicPacket, client, CryptoState),
    lager:debug("sending packet with number ~p (encoded size ~p)",
                [quic_packet:packet_number(QuicPacket), iolist_size(Data)]),
    ok = gen_udp:send(Socket, RemoteIpAddress, RemotePort, Data).

outbound_packet_crypto_state(#outbound_regular_packet{ crypto_state = current },
                             CurrentCryptoState) ->
    CurrentCryptoState;
outbound_packet_crypto_state(#outbound_regular_packet{ crypto_state = OverridenCryptoState },
                             _CurrentCryptoState) ->
    OverridenCryptoState;
outbound_packet_crypto_state(_QuicPacket, CurrentCryptoState) ->
    CurrentCryptoState.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
maybe_setup_connection(#state{ remote_hostname = RemoteHostname } = State) ->
    case lookup_ip_address(RemoteHostname) of
        {ok, RemoteIpAddress} ->
            NewState = setup_connection(State, RemoteIpAddress),
            {noreply, NewState};
        {error, Error} ->
            {stop, {shutdown, Error}, State}
    end.

setup_connection(#state{ crypto_state = undefined,
                         inflow_pid = undefined,
                         outflow_pid = undefined } = State,
                 RemoteIpAddress) ->
    SupervisorPid = State#state.component_supervisor_pid,
    ConnectionId = crypto:rand_uniform(0, 1 bsl 64),

    {ok, {InflowPid, OutflowPid}} =
        quic_connection_components_sup:start_remaining_components(
          SupervisorPid, self(), ConnectionId,
          ?CRYPTO_STREAM_ID, ?MODULE, self()),

    PingInterval = ?DEFAULT_PING_INTERVAL,
    IdleTimeout = PingInterval * 2,
    PingTimer = erlang:send_after(timer:seconds(PingInterval), self(), send_ping),
    State#state{ remote_ip_address = RemoteIpAddress,
                 crypto_state = quic_crypto:initial_state(ConnectionId, IdleTimeout),
                 inflow_pid = InflowPid,
                 inflow_monitor = monitor(process, InflowPid),
                 outflow_pid = OutflowPid,
                 outflow_monitor = monitor(process, OutflowPid),
                 ping_timer = PingTimer,
                 ping_interval = PingInterval }.

-spec handle_received_data(binary(), state()) -> state().
handle_received_data(Data, State) ->
    CryptoState = State#state.crypto_state,
    {Packet, NewCryptoState} = quic_packet:decode(Data, server, CryptoState),
    InflowPid = State#state.inflow_pid,
    ok = quic_inflow:dispatch_packet(InflowPid, Packet),
    State#state{ crypto_state = NewCryptoState }.

lookup_ip_address(Hostname) ->
    % TODO: handle IPv6
    case inet:getaddr(Hostname, inet) of
        {ok, Ipv4Address} -> {ok, Ipv4Address};
        {error, Ipv4Err} -> {error, Ipv4Err}
    end.
