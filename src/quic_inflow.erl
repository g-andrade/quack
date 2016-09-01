-module(quic_inflow).

-include("quic_frame.hrl").
-include("quic_packet.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]). -ignore_xref({start_link,2}).
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
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          outflow_pid :: pid(),
          % @TODO: we need a more performant data structure for this,
          % otherwise out-of-order packets will kill performance
          inbound_packet_blocks :: [inbound_packet_block()],
          stream_pids :: #{stream_id() => pid()}
         }).
-type state() :: #state{}.
-export_type([state/0]).

-record(inbound_packet_block, {
          smallest_packet_number :: packet_number(),
          largest_packet_number :: packet_number(),
          largest_packet_number_timestamp :: non_neg_integer() % in microseconds
         }).
-type inbound_packet_block() :: #inbound_packet_block{}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(OutflowPid, InitialStreams) ->
    gen_server:start_link(?CB_MODULE, [OutflowPid, InitialStreams], []).

-spec dispatch_packet(InflowPid :: pid(), quic_packet()) -> ok.
dispatch_packet(InflowPid, Packet) ->
    gen_server:cast(InflowPid, {packet, Packet}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([OutflowPid, InitialStreams]) ->
    InitialState =
        #state{
           outflow_pid = OutflowPid,
           inbound_packet_blocks = [],
           stream_pids = InitialStreams
          },
    {ok, InitialState}.

handle_call(Request, From, State) ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast({packet, Packet}, State) ->
    NewState = on_inbound_packet(Packet, State),
    {noreply, NewState};
handle_cast(Msg, State) ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

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

-spec on_inbound_packet(regular_packet(), state()) -> state().
on_inbound_packet(#regular_packet{ packet_number = PacketNumber } = Packet,
                  #state{ inbound_packet_blocks = InboundPacketBlocks } = State) ->
    case put_in_inbound_blocks(PacketNumber, InboundPacketBlocks) of
        repeated ->
            lager:debug("ignoring repeated packet with number ~p", [PacketNumber]),
            State;
        {OrderCategory, NewInboundPacketBlocks} ->
            lager:debug("accepting packet with number ~p (~p)",
                        [PacketNumber, OrderCategory]),
            OutflowPid = State#state.outflow_pid,
            NewState = State#state{ inbound_packet_blocks = NewInboundPacketBlocks },
            AckFrame = generate_ack_frame(NewState#state.inbound_packet_blocks),
            quic_outflow:dispatch_frame(OutflowPid, AckFrame),
            handle_received_packet(Packet, NewState)
    end.

-spec handle_received_packet(quic_packet(), state()) -> state().
handle_received_packet(#regular_packet{ frames = Frames }, State) ->
    lists:foldl(
      fun (Frame, StateAcc) ->
              handle_received_frame(Frame, StateAcc)
      end,
      State,
      Frames).

-spec handle_received_frame(frame(), state()) -> state().
handle_received_frame(Frame, State)
  when is_record(Frame, stream_frame) ->
    StreamId = Frame#stream_frame.stream_id,
    StreamPid = maps:get(StreamId, State#state.stream_pids),
    quic_stream:dispatch_inbound_frame(StreamPid, Frame),
    State;
handle_received_frame(Frame, State)
  when is_record(Frame, ack_frame) ->
    OutflowPid = State#state.outflow_pid,
    quic_outflow:dispatch_inbound_ack(OutflowPid, Frame),
    State;
handle_received_frame(Frame, State)
  when is_record(Frame, stop_waiting_frame) ->
    lager:debug("got stop_waiting_frame: ~p", [Frame]),
    handle_stop_waiting(Frame, State);
handle_received_frame(Frame, State)
  when is_record(Frame, padding_frame) ->
    % ignore
    State.

handle_stop_waiting(StopWaitingFrame, State) ->
    StopWaitingPacketNumber = StopWaitingFrame#stop_waiting_frame.least_unacked_packet_number,
    InboundPacketBlocks = State#state.inbound_packet_blocks,
    NewInboundPacketBlocks =
        lists:dropwhile(
          fun (#inbound_packet_block{ largest_packet_number = LargestPacketNumber }) ->
                  LargestPacketNumber < StopWaitingPacketNumber
          end,
          InboundPacketBlocks),
    State#state{ inbound_packet_blocks = NewInboundPacketBlocks }.

generate_ack_frame([NewestBlock | _] = InboundPacketBlocks) ->
    [OldestBlock | RemainingBlocks] =lists:reverse(InboundPacketBlocks),

    #inbound_packet_block{
       largest_packet_number = LargestReceived,
       largest_packet_number_timestamp = LargestReceivedTimestamp
      } = NewestBlock,
    LargestReceivedTimeDelta = quic_util:now_us() - LargestReceivedTimestamp,

    FirstAckReceivedPacketBlock =
        #ack_received_packet_block{
           gap_from_prev_block = 0,
           ack_block_length = (OldestBlock#inbound_packet_block.largest_packet_number -
                               OldestBlock#inbound_packet_block.smallest_packet_number)
        },

    {NthAckReceivedPacketBlocks, _} =
        lists:mapfoldl(
          fun (PacketBlock, PrevPacketBlock) ->
                Gap = (PacketBlock#inbound_packet_block.smallest_packet_number -
                       PrevPacketBlock#inbound_packet_block.largest_packet_number),

                Length = (PacketBlock#inbound_packet_block.largest_packet_number -
                          PacketBlock#inbound_packet_block.smallest_packet_number),

                % in case more than 256 packets were lost
                NormalizedGap = case Gap > 256 of
                                    true -> 0;
                                    false -> Gap
                                end,

                {#ack_received_packet_block{
                    gap_from_prev_block = NormalizedGap,
                    ack_block_length = Length },
                 PrevPacketBlock}
          end,
          OldestBlock,
          RemainingBlocks),

    #ack_frame{
       largest_received = LargestReceived,
       largest_received_time_delta = LargestReceivedTimeDelta,
       received_packet_blocks = [FirstAckReceivedPacketBlock | NthAckReceivedPacketBlocks],
       packet_timestamps = [] % still not using these
      }.


put_in_inbound_blocks(PacketNumber, L) ->
    put_in_inbound_blocks(PacketNumber, L, []).

put_in_inbound_blocks(PacketNumber, [H | T], [] = _RevAcc)
  when PacketNumber =:= (H#inbound_packet_block.largest_packet_number + 1) ->
    % contiguous packet
    ChangedH =
        H#inbound_packet_block{ largest_packet_number = PacketNumber,
                                largest_packet_number_timestamp = quic_util:now_us() },
    {contiguous, [ChangedH | T]};
put_in_inbound_blocks(PacketNumber, [H | _] = L, [] = _RevAcc)
  when PacketNumber > (H#inbound_packet_block.largest_packet_number + 1) ->
    % packet arrived before time
    NewH =
        #inbound_packet_block{ smallest_packet_number = PacketNumber,
                               largest_packet_number = PacketNumber,
                               largest_packet_number_timestamp = quic_util:now_us() },
    {premature, [NewH | L]};
put_in_inbound_blocks(PacketNumber, [H | _], _RevAcc)
  when PacketNumber >= H#inbound_packet_block.smallest_packet_number,
       PacketNumber =< H#inbound_packet_block.largest_packet_number ->
    % packet is repeated
    repeated;
put_in_inbound_blocks(PacketNumber, [H | _] = L, [PrevH | _] = RevAcc)
  when PacketNumber < PrevH#inbound_packet_block.smallest_packet_number,
       PacketNumber > H#inbound_packet_block.largest_packet_number ->
    % delayed and non-contiguous
    NewH =
        #inbound_packet_block{ smallest_packet_number = PacketNumber,
                               largest_packet_number = PacketNumber,
                               largest_packet_number_timestamp = quic_util:now_us() },
    {delayed, lists:reverse(RevAcc) ++ [NewH | L]};
put_in_inbound_blocks(PacketNumber, [H | T], RevAcc)
  when PacketNumber < H#inbound_packet_block.smallest_packet_number ->
    % delayed packet
    put_in_inbound_blocks(PacketNumber, T, [H | RevAcc]);
put_in_inbound_blocks(PacketNumber, [], RevAcc) ->
    % delayed packet and non-contiguious
    NewH =
        #inbound_packet_block{ smallest_packet_number = PacketNumber,
                               largest_packet_number = PacketNumber,
                               largest_packet_number_timestamp = quic_util:now_us() },
    {delayed, lists:reverse([NewH | RevAcc])}.
