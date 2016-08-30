-module(quic_connection).
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

-define(CRYPTO_NEGOTIATION_STREAM_ID, 1).

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

          connection_id :: uint64(),
          outbound_packet_number :: uint64(),
          %crypto_state :: quic_crypto:state(),
          flow_state :: quic_flow:state(),
          crypto_stream :: quic_stream:state(),
          regular_streams :: #{stream_id() => quic_stream:state()}
         }).
-type state() :: #state{}.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type stream_reaction() :: ({change_state, NewState :: term()} |
                            {send, Data :: iodata()} |
                            {send, Data :: iodata(), OptionalHeaders :: [optional_header()]}).
-export_type([stream_reaction/0]).

-type optional_header() :: ({version, iodata()} |               % 4 bytes
                            {diversification_nonce, iodata()}). % 32 bytes
-export_type([optional_header/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(ControllingPid, RemoteHostname, RemotePort) ->
    gen_server:start_link(?CB_MODULE, [ControllingPid, RemoteHostname, RemotePort], []).

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
handle_cast(Msg, State) ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

handle_info({udp_passive, Socket}, #state{ socket = Socket } = State) ->
    ok = inet:setopts(Socket, [{active, once}]),
    {noreply, State};
handle_info({udp, Socket, _SenderIp, _SenderPort, Data}, #state{ socket = Socket } = State) ->
    {noreply, handle_received_data(Data, State)};
handle_info({'DOWN', Reference, process, _Pid, _Reason}, State)
  when Reference =:= State#state.controlling_pid_monitor ->
    {stop, oops, State};
handle_info({send_packet, QuicPacket}, State) ->
    send_packet(QuicPacket, State),
    {noreply, State};
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
-spec send_packet(quic_packet(), state()) -> state().
send_packet(QuicPacket, State) ->
    #state{ remote_hostname = RemoteHostname,
            remote_port = RemotePort,
            socket = Socket } = State,

    {Data, NewCryptoState} = quic_packet:encode(QuicPacket, client, crypto_state(State)),
    %lager:debug("sending packet (encoded size ~p): ~p", [iolist_size(Data), QuicPacket]),
    ok = gen_udp:send(Socket, RemoteHostname, RemotePort, Data),
    set_crypto_state(State, NewCryptoState).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_frame(stream_frame(), state()) -> state().
send_frame(Frame, State) ->
    send_frame(Frame, State, []).

-spec send_frame(stream_frame(), state(),
                 OptionalHeaders :: [{version_header | diversification_nonce_header, iodata()}])
        -> state().
send_frame(Frame, State, OptionalHeaders) ->
    PrevPacketNumber = State#state.outbound_packet_number,
    NewPacketNumber = PrevPacketNumber + 1,
    NewState = State#state{ outbound_packet_number = NewPacketNumber },
    Packet = #regular_packet{
                connection_id = State#state.connection_id,
                version = proplists:get_value(version_header, OptionalHeaders),
                diversification_nonce = proplists:get_value(diversification_nonce_header, OptionalHeaders),
                packet_number = NewPacketNumber,
                frames = [Frame]},
    send_packet(Packet, NewState).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_stream_data(stream_id(), iodata(), state())
        -> state().
send_stream_data(StreamId, Data, State) ->
    send_stream_data(StreamId, Data, State, []).

-spec send_stream_data(stream_id(), iodata(), state(), [optional_header()])
        -> state().
send_stream_data(StreamId, Data, State, OptionalHeaders) ->
    StreamState = stream_state(StreamId, State),
    {Offset, NewStreamState} = quic_stream:on_outbound_data(Data, StreamState),
    NewState = set_stream_state(StreamId, State, NewStreamState),
    StreamFrame = #stream_frame{ stream_id = StreamId,
                                 offset = Offset,
                                 data_payload = Data },
    send_frame(StreamFrame, NewState, OptionalHeaders).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec setup_connection(state()) -> state().
setup_connection(#state{ connection_id = undefined,
                         crypto_stream = undefined,
                         outbound_packet_number = undefined } = State) ->
        %-> {Reactions :: [quic_connection:stream_reaction()], State :: state()}.
    StreamId = ?CRYPTO_NEGOTIATION_STREAM_ID,
    ConnectionId = crypto:rand_uniform(0, 1 bsl 64),
    FlowState = quic_flow:initial_state(),
    {CryptoStreamReactions, CryptoStream} = quic_crypto:on_start(StreamId, ConnectionId),
    NewState = State#state{ connection_id = ConnectionId,
                            outbound_packet_number = 0,
                            flow_state = FlowState,
                            crypto_stream = CryptoStream },
    handle_stream_reactions(StreamId, CryptoStreamReactions, NewState).

-spec handle_received_data(binary(), state()) -> state().
handle_received_data(Data, State) ->
    CryptoState = crypto_state(State),
    {Packet, NewCryptoState} = quic_packet:decode(Data, server, CryptoState),
    FlowReactions = quic_flow:on_receive_packet(Packet, State#state.flow_state),
    %lager:debug("got packet: ~p", [QuicPacket]),
    NewState = set_crypto_state(State, NewCryptoState),
    handle_flow_reactions(FlowReactions, NewState).

-spec handle_received_packet(quic_packet(), state()) -> state().
handle_received_packet(#regular_packet{ packet_number = PacketNumber,
                                        frames = Frames }, State) ->
    lists:foldl(
      fun (Frame, StateAcc) ->
              handle_received_frame(PacketNumber, Frame, StateAcc)
      end,
      State,
      Frames).

-spec handle_received_frame(packet_number(), frame(), state()) -> state().
handle_received_frame(_PacketNumber, Frame, State)
  when is_record(Frame, stream_frame) ->
    #stream_frame{ stream_id = StreamId,
                   offset = Offset,
                   data_payload = Data } = Frame,

    StreamState = stream_state(StreamId, State),
    {Reactions, NewStreamState} = quic_stream:on_inbound_data(Offset, Data, StreamState),
    NewState = set_stream_state(StreamId, State, NewStreamState),
    %lager:debug_unsafe("handling reactions: ~p~nfor for stream state ~p",
    %                   [Reactions, NewStreamState]),
    handle_stream_reactions(StreamId, Reactions, NewState);
handle_received_frame(_PacketNumber, Frame, State)
  when is_record(Frame, ack_frame) ->
    % @TODO
    lager:debug("got ack frame: ~p", [lager:pr(Frame, ?MODULE)]),
    State;
handle_received_frame(PacketNumber, Frame, State)
  when is_record(Frame, stop_waiting_frame) ->
    lager:debug("got stop_waiting_frame: ~p", [Frame]),
    FlowState = State#state.flow_state,
    FlowReactions = quic_flow:on_receive_stop_waiting(PacketNumber, Frame, FlowState),
    handle_flow_reactions(FlowReactions, State);
handle_received_frame(_PacketNumber, Frame, State)
  when is_record(Frame, padding_frame) ->
    % ignore
    State.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec handle_stream_reactions(stream_id(), [stream_reaction()], state()) -> state().
handle_stream_reactions(StreamId, Reactions, State) ->
    lists:foldl(
      fun (Reaction, StateAcc) ->
              handle_stream_reaction(StreamId, Reaction, StateAcc)
      end,
      State,
      Reactions).

-spec handle_stream_reaction(stream_id(), stream_reaction(), state()) -> state().
handle_stream_reaction(StreamId, {change_state, NewStreamState}, State) ->
    set_stream_state(StreamId, State, NewStreamState);
handle_stream_reaction(StreamId, {send, Data}, State) ->
    send_stream_data(StreamId, Data, State);
handle_stream_reaction(StreamId, {send, Data, OptionalHeaders}, State) ->
    send_stream_data(StreamId, Data, State, OptionalHeaders).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_flow_reactions(Reactions, State) ->
    lists:foldl(fun handle_flow_reaction/2, State, Reactions).

handle_flow_reaction({handle_received_packet, Packet}, State) ->
    handle_received_packet(Packet, State);
handle_flow_reaction({change_state, NewFlowState}, State) ->
    State#state{ flow_state = NewFlowState };
handle_flow_reaction({send, {frame, Frame}}, State) ->
    send_frame(Frame, State).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
crypto_state(#state{ crypto_stream = CryptoStream }) ->
    quic_stream:callback_state(CryptoStream).

set_crypto_state(#state{ crypto_stream = CryptoStream } = State, CryptoState) ->
    NewCryptoStream = quic_stream:set_callback_state(CryptoStream, CryptoState),
    State#state{ crypto_stream = NewCryptoStream }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
stream_state(StreamId, State) when StreamId =:= ?CRYPTO_NEGOTIATION_STREAM_ID ->
    State#state.crypto_stream;
stream_state(StreamId, State) ->
    RegularStreams = State#state.regular_streams,
    maps:get(StreamId, RegularStreams).

set_stream_state(StreamId, State, StreamState) when StreamId =:= ?CRYPTO_NEGOTIATION_STREAM_ID ->
    State#state{ crypto_stream = StreamState };
set_stream_state(StreamId, State, StreamState) ->
    RegularStreams = State#state.regular_streams,
    NewRegularStreams = maps:put(StreamId, StreamState, RegularStreams),
    State#state{ regular_streams = NewRegularStreams }.
