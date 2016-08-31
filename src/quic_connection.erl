-module(quic_connection).
-behaviour(quic_crypto_state_subscriber).
-behaviour(gen_server).

-include("quic.hrl").
-include("quic_data_kv.hrl").
-include("quic_frame.hrl").
-include("quic_packet.hrl").
-include("quic_numeric.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/3]). -ignore_xref({start_link,3}).
-export([dispatch_packet/2]).

%% ------------------------------------------------------------------
%% quic_crypto_state_subscriber Function Exports
%% ------------------------------------------------------------------

-export([notify_new_crypto_shadow/2]).

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
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

-define(CRYPTO_STREAM_ID, 1).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          controlling_pid :: pid(),
          controlling_pid_monitor :: reference(),
          remote_hostname :: inet:hostname(),
          remote_port :: inet:port_number(),
          remote_sni :: iodata(),
          socket :: inet:socket(),

          inflow_pid :: pid(),
          outflow_pid :: pid(),
          crypto_pid :: pid(),
          crypto_shadow_state :: quic_crypto:shadow_state()
         }).
-type state() :: #state{}.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type optional_packet_header() :: outflow:optional_packet_header().
-export_type([optional_packet_header/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(ControllingPid, RemoteHostname, RemotePort) ->
    gen_server:start_link(?CB_MODULE, [ControllingPid, RemoteHostname, RemotePort], []).

-spec dispatch_packet(pid(), quic_packet()) -> ok.
dispatch_packet(ConnectionPid, Packet) ->
    gen_server:cast(ConnectionPid, {dispatch_packet, Packet}).

%% ------------------------------------------------------------------
%% quic_crypto_state_subscriber Function Definitions
%% ------------------------------------------------------------------

-spec notify_new_crypto_shadow(pid(), quic_crypto:shadow_state()) -> ok.
notify_new_crypto_shadow(ConnectionPid, CryptoShadowState) ->
    gen_server:cast(ConnectionPid, {notify_new_crypto_shadow, CryptoShadowState}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([ControllingPid, RemoteHostname, RemotePort]) ->
    UdpOpts = [{active, 10},
               {mode, binary}],
    {ok, Socket} = gen_udp:open(0, UdpOpts),
    gen_server:cast(self(), setup_connection),
    {ok, #state{
            controlling_pid = ControllingPid,
            controlling_pid_monitor = monitor(process, ControllingPid),
            remote_hostname = RemoteHostname,
            remote_port = RemotePort,
            socket = Socket }}.

handle_call(Request, From, State) ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast(setup_connection, State) ->
    {noreply, setup_connection(State)};
handle_cast({dispatch_packet, QuicPacket}, State) ->
    send_packet(QuicPacket, State),
    {noreply, State};
handle_cast({notify_new_crypto_shadow, CryptoShadowState}, State) ->
    NewState = State#state{ crypto_shadow_state = CryptoShadowState },
    {noreply, NewState};
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
handle_info(Info, State) ->
    lager:debug("unhandled info ~p on state ~p", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_packet(quic_packet(), state()) -> ok.
send_packet(QuicPacket, State) ->
    #state{ remote_hostname = RemoteHostname,
            remote_port = RemotePort,
            socket = Socket } = State,

    Data = quic_packet:encode(QuicPacket, client, State#state.crypto_shadow_state),
    lager:debug("sending packet with number ~p (encoded size ~p)",
                [quic_packet:packet_number(QuicPacket), iolist_size(Data)]),
    ok = gen_udp:send(Socket, RemoteHostname, RemotePort, Data).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec setup_connection(state()) -> state().
setup_connection(#state{ inflow_pid = undefined,
                         outflow_pid = undefined } = State) ->
        %-> {Reactions :: [quic_connection:stream_reaction()], State :: state()}.
    ConnectionId = crypto:rand_uniform(0, 1 bsl 64),
    {ok, OutflowPid} = quic_outflow:start_link(self(), ConnectionId),
    {ok, CryptoPid} = quic_crypto:start_link(ConnectionId),
    {ok, CryptoShadowState} = quic_crypto:subscribe_shadow_state(CryptoPid, ?MODULE, self()),
    {ok, CryptoStreamPid} = 
        quic_stream:start_link(?CRYPTO_STREAM_ID, OutflowPid,
                               quic_crypto, CryptoPid),
    {ok, InflowPid} = 
        quic_inflow:start_link(OutflowPid, #{?CRYPTO_STREAM_ID => CryptoStreamPid}),

    State#state{ inflow_pid = InflowPid,
                 outflow_pid = OutflowPid,
                 crypto_pid = CryptoPid,
                 crypto_shadow_state = CryptoShadowState }.

-spec handle_received_data(binary(), state()) -> state().
handle_received_data(Data, State) ->
    CryptoShadowState = State#state.crypto_shadow_state,
    {Packet, NewCryptoShadowState} = quic_packet:decode(Data, server, CryptoShadowState),
    InflowPid = State#state.inflow_pid,
    ok = quic_inflow:receive_packet(InflowPid, Packet),
    State#state{ crypto_shadow_state = NewCryptoShadowState }.
