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
          crypto_state :: quic_crypto:state(),

          inbound_streams = #{} :: #{stream_id() => inbound_stream_state()},
          outbound_streams = #{} :: #{stream_id() => outbound_stream_state()}
         }).
-type state() :: #state{}.

-record(inbound_stream_state, {
          pending_data :: iolist(),
          expected_offset :: non_neg_integer()
         }).
-type inbound_stream_state() :: #inbound_stream_state{}.

-record(outbound_stream_state, {
          offset :: non_neg_integer()
         }).
-type outbound_stream_state() :: #outbound_stream_state{}.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

%-type conn_state() :: unverified_server | waiting_server_rej() | waiting_server_hello() | ready.

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
    {Data, NewCryptoState} = quic_packet:encode(QuicPacket, client, State#state.crypto_state),
    %lager:debug("sending packet (encoded size ~p): ~p", [iolist_size(Data), QuicPacket]),
    ok = gen_udp:send(Socket, RemoteHostname, RemotePort, Data),
    State#state{ crypto_state = NewCryptoState }.

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
-spec send_stream_data_payload(stream_id(), iodata(), state())
        -> state().
send_stream_data_payload(StreamId, DataPayload, State) ->
    send_stream_data_payload(StreamId, DataPayload, State, []).

-spec send_stream_data_payload(stream_id(), iodata(), state(),
                               OptionalHeaders :: [{version_header | diversification_nonce_header, iodata()}])
        -> state().
send_stream_data_payload(StreamId, DataPayload,
                         #state{ outbound_streams = OutboundStreams } = State,
                         OptionalHeaders) ->

    PrevStreamState = maps:get(StreamId, OutboundStreams, #outbound_stream_state{ offset = 0 }),
    PrevOffset = PrevStreamState#outbound_stream_state.offset,
    %EncodedDataPayload = quic_data_kv:encode(DataPayload),
    NewOffset = PrevOffset + iolist_size(DataPayload),
    NewStreamState = PrevStreamState#outbound_stream_state{ offset = NewOffset },
    NewOutboundStreams = maps:put(StreamId, NewStreamState, OutboundStreams),

    NewState = State#state{ outbound_streams = NewOutboundStreams },
    StreamFrame = #stream_frame{ stream_id = StreamId,
                                 offset = PrevOffset,
                                 data_payload = DataPayload },
    send_frame(StreamFrame, NewState, OptionalHeaders).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec send_stream_data_kv(stream_id(), data_kv(), state())
        -> state().
send_stream_data_kv(StreamId, DataKv, State) ->
    send_stream_data_kv(StreamId, DataKv, State, []).

-spec send_stream_data_kv(stream_id(), data_kv(), state(),
                          OptionalHeaders :: [{version_header | diversification_nonce_header, iodata()}])
        -> state().
send_stream_data_kv(StreamId, DataKv, State, OptionalHeaders) ->
    DataPayload = quic_data_kv:encode(DataKv),
    send_stream_data_payload(StreamId, DataPayload, State, OptionalHeaders).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-spec setup_connection(state()) -> state().
setup_connection(#state{ connection_id = undefined,
                         crypto_state = undefined,
                         outbound_packet_number = undefined } = State) ->
    ConnectionId = crypto:rand_uniform(0, 1 bsl 64),
    Reactions = quic_crypto:on_start(ConnectionId),
    NewState = State#state{ connection_id = ConnectionId,
                            outbound_packet_number = 0 },
    handle_stream_reactions(?CRYPTO_NEGOTIATION_STREAM_ID, Reactions, NewState,
                            #state.crypto_state).

-spec handle_received_data(binary(), state()) -> state().
handle_received_data(Data, State) ->
    {Packet, NewCryptoState} = quic_packet:decode(Data, server, State#state.crypto_state),
    %lager:debug("got packet: ~p", [QuicPacket]),
    handle_received_packet(Packet, State#state{ crypto_state = NewCryptoState }).

-spec handle_received_packet(quic_packet(), state()) -> state().
handle_received_packet(#regular_packet{ frames = Frames }, State) ->
    lists:foldl(fun handle_received_frame/2, State, Frames).

-spec handle_received_frame(frame(), state()) -> state().
handle_received_frame(#stream_frame{} = Frame, #state{ inbound_streams = InboundStreams } = State) ->
    #stream_frame{ stream_id = StreamId,
                   offset = Offset,
                   data_payload = DataPayload } = Frame,
    lager:debug("got frame for stream ~p / offset ~p / length ~p", [StreamId, Offset, iolist_size(DataPayload)]),
    {CompleteDataPayload, StreamState2} =
        case maps:find(StreamId, InboundStreams) of
            {ok, #inbound_stream_state{ pending_data = PrevPendingData,
                                        expected_offset = ExpectedOffset } = StreamState} ->
                ?ASSERT(Offset =:= ExpectedOffset,
                        {unconsecutive_stream_frames_are_unsupported_yet,
                         [{offset, Offset},
                          {expected_offset, ExpectedOffset},
                          {size_prev_pending_data, iolist_size(PrevPendingData)}]}),
                {iolist_to_binary([PrevPendingData, DataPayload]),
                 StreamState#inbound_stream_state{ pending_data = "",
                                                   expected_offset = Offset + byte_size(DataPayload) }};
            error ->
                {DataPayload,
                 #inbound_stream_state{ pending_data = "",
                                        expected_offset = Offset + byte_size(DataPayload) }}
        end,

    case quic_data_kv:decode(CompleteDataPayload) of
        #data_kv{} = DataKv ->
            NewInboundStreams = maps:put(StreamId, StreamState2, InboundStreams),
            NewState = State#state{ inbound_streams = NewInboundStreams },
            handle_inbound_stream(StreamId, DataKv, NewState);
        incomplete ->
            lager:debug("ignoring incomplete stream frame for stream ~p", [StreamId]),
            StreamState3 = StreamState2#inbound_stream_state{
                             pending_data = CompleteDataPayload
                             % @TODO: it can be so much improved
                             },

            NewInboundStreams = maps:put(StreamId, StreamState3, InboundStreams),
            State#state{ inbound_streams = NewInboundStreams }
    end;
handle_received_frame(#ack_frame{} = AckFrame, State) ->
    % @TODO
    lager:debug("got ack frame: ~p", [lager:pr(AckFrame, ?MODULE)]),
    State;
handle_received_frame(#stop_waiting_frame{} = StopWaitingFrame, State) ->
    % @TODO
    lager:debug("got stop_waiting_frame: ~p", [StopWaitingFrame]),
    State;
handle_received_frame(#padding_frame{}, State) ->
    % ignore
    State.

-spec handle_inbound_stream(StreamId :: uint32(),
                            DataKv :: data_kv(),
                            State :: state()) -> state().
handle_inbound_stream(StreamId, DataKv, State)
  when StreamId =:= ?CRYPTO_NEGOTIATION_STREAM_ID ->
    CryptoState = State#state.crypto_state,
    Reaction = quic_crypto:on_data_kv(DataKv, CryptoState),
    handle_stream_reactions(StreamId, Reaction, State, #state.crypto_state).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_stream_reactions(StreamId, Reactions, State, SubStateKey) ->
    lists:foldl(
      fun (Reaction, StateAcc) ->
              handle_stream_reaction(StreamId, Reaction, StateAcc, SubStateKey)
      end,
      State,
      Reactions).

handle_stream_reaction(StreamId, {reply, {data_payload, DataPayload}}, State, _SubStateKey) ->
    send_stream_data_payload(StreamId, DataPayload, State);
handle_stream_reaction(StreamId, {reply, {data_payload, DataPayload}, OptionalHeaders}, State, _SubStateKey) ->
    send_stream_data_payload(StreamId, DataPayload, State, OptionalHeaders);
handle_stream_reaction(StreamId, {reply, {data_kv, DataKv}}, State, _SubStateKey) ->
    send_stream_data_kv(StreamId, DataKv, State);
handle_stream_reaction(StreamId, {reply, {data_kv, DataPayload}, OptionalHeaders}, State, _SubStateKey) ->
    send_stream_data_kv(StreamId, DataPayload, State, OptionalHeaders);
handle_stream_reaction(_StreamId, {change_state, NewSubState}, State, SubStateKey) ->
    setelement(SubStateKey, State, NewSubState).
