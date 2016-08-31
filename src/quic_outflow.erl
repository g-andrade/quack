-module(quic_outflow).

-include("quic_frame.hrl").
-include("quic_packet.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([initial_state/1]).
-export([on_inbound_ack_frame/2]).
-export([on_outbound_frame/3]).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          connection_id :: connection_id(),
          prev_packet_number :: packet_number(),
          % @TODO: use a more performant data structure for this?
          unacked_packets :: [unacked_packet()]
         }).
-type state() :: #state{}.
-export_type([state/0]).

-record(unacked_packet, {
          packet_number :: packet_number(),
          timestamp :: non_neg_integer(), % in microseconds
          packet :: regular_packet()
         }).
-type unacked_packet() :: #unacked_packet{}.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type optional_packet_header() :: ({version, iodata()} |               % 4 bytes
                                   {diversification_nonce, iodata()}). % 32 bytes
-export_type([optional_packet_header/0]).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-spec initial_state(ConnectionId :: connection_id()) -> state().
initial_state(ConnectionId) ->
    #state{
       connection_id = ConnectionId,
       prev_packet_number = 0,
       unacked_packets = [] }.

-spec on_inbound_ack_frame(AckFrame :: ack_frame(), State :: state())
        -> {Reactions :: [quic_connection:outflow_reaction()], NewState :: state()}.
on_inbound_ack_frame(AckFrame, State) ->
    % @TODO: look at largest_received_time_delta to ease of resending
    #ack_frame{
       largest_received = LargestReceivedPacketNumber,
       received_packet_blocks = ReceivedPacketBlocks } = AckFrame,

    lager:debug("got ack: largest received ~p, packet blocks ~p",
                [LargestReceivedPacketNumber, ReceivedPacketBlocks]),
    UnackedPackets = State#state.unacked_packets,
    debug_unacked_packet_numbers("old unacked packets: ", UnackedPackets),
    NewUnackedPackets =
        filter_unacked_packets(UnackedPackets, LargestReceivedPacketNumber,
                               ReceivedPacketBlocks),
    debug_unacked_packet_numbers("new unacked packets: ", NewUnackedPackets),
    NewState = State#state{ unacked_packets = NewUnackedPackets },
    resend_all_below_largest_received(LargestReceivedPacketNumber, NewState).

-spec on_outbound_frame(Frame :: frame(),
                        State :: state(),
                        OptionalPacketHeaders :: optional_packet_header())
        -> {Reactions :: [quic_connection:outflow_reaction()], NewState :: state()}.
on_outbound_frame(Frame, State, OptionalPacketHeaders) ->
    #state{ connection_id = ConnectionId } = State,
    Packet =
        #regular_packet{
           connection_id = ConnectionId,
           version = proplists:get_value(version, OptionalPacketHeaders),
           diversification_nonce = proplists:get_value(diversification_nonce, OptionalPacketHeaders),
           frames = [Frame] },
    on_outbound_packet(Packet, State).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec on_outbound_packet(NumberlessPacket :: regular_packet(), State :: state())
        -> {Reactions :: [quic_connection:outflow_reaction()], NewState :: state()}.
on_outbound_packet(NumberlessPacket, State) ->
    #state{ prev_packet_number = PrevPacketNumber,
            unacked_packets = UnackedPackets } = State,
    PacketNumber = PrevPacketNumber + 1,
    Packet = NumberlessPacket#regular_packet{ packet_number = PacketNumber },
    UnackedPacket =
        #unacked_packet{
           packet_number = PacketNumber,
           timestamp = quic_util:now_us(),
           packet = Packet },
    NewUnackedPackets = [UnackedPacket | UnackedPackets],
    NewState =
        State#state{
          prev_packet_number = PacketNumber,
          unacked_packets = NewUnackedPackets },

    Reactions = [{send_packet, Packet}],
    {Reactions, NewState}.
filter_unacked_packets(UnackedPackets, LargestReceivedPacketNumber, ReceivedPacketBlocks) ->
    {RecentUnacked, RemainingPackets} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber > LargestReceivedPacketNumber
          end,
          UnackedPackets),

    RecentUnacked ++
        filter_old_unacked_packets(RemainingPackets, LargestReceivedPacketNumber,
                                   ReceivedPacketBlocks).

filter_old_unacked_packets([] = UnackedPackets, _ReceivedPacketNumber,
                           _Blocks) ->
    UnackedPackets;
filter_old_unacked_packets(UnackedPackets, _ReceivedPacketNumber,
                           [] = _Blocks) ->
    UnackedPackets;
filter_old_unacked_packets(UnackedPackets, ReceivedPacketNumber,
                           [FirstBlock | RemainingBlocks]) ->
    #ack_received_packet_block{ gap_from_prev_block = GapFromPrevBlock,
                                ack_block_length = BlockLength } = FirstBlock,

    UnreceivedFloor = ReceivedPacketNumber - GapFromPrevBlock,
    {Unacked, RemainingPackets} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber > UnreceivedFloor
          end,
          UnackedPackets),

    ReceivedFloor = UnreceivedFloor - BlockLength,
    {_Acked, NextUnacked} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber >= ReceivedFloor
          end,
          RemainingPackets),

    Unacked ++ filter_unacked_packets(NextUnacked, ReceivedFloor, RemainingBlocks).

debug_unacked_packet_numbers(Msg, UnackedPackets) ->
    lager:debug("~s~p",
                [Msg,
                 list_to_tuple([UnackedPacket#unacked_packet.packet_number
                                || UnackedPacket <- UnackedPackets])]).

%
% @TODO actually rate limit this? (as well as sending in general)
%
resend_all_below_largest_received(LargestReceivedPacketNumber, State) ->
    UnackedPackets = State#state.unacked_packets,
    {NewUnackedPackets, UnackedPacketsToResend} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber >= LargestReceivedPacketNumber
          end,
          UnackedPackets),
    StateB = State#state{ unacked_packets = NewUnackedPackets },

    case UnackedPacketsToResend of
        [] ->
            % nothing to do
            {[], StateB};
        [#unacked_packet{ packet_number = HighestResendingPacketNumber } | _] ->
            debug_unacked_packet_numbers("resending packets ", UnackedPacketsToResend),
            StopWaitingPacketNumber = HighestResendingPacketNumber + 1,
            PacketsToResend =
                lists:foldl(
                  fun (#unacked_packet{ packet = Packet }, Acc) ->
                          [Packet | Acc]
                  end,
                  [],
                  UnackedPacketsToResend),

            StopWaitingFrame =
                #stop_waiting_frame{
                   least_unacked_packet_number = StopWaitingPacketNumber },
            {StopWaitingFrameReactions, StateC} =
                on_outbound_frame(StopWaitingFrame, StateB, []),

            {ResendReactionsList, StateD} =
                lists:mapfoldl(
                  fun (Packet, StateAcc) ->
                          on_outbound_packet(Packet, StateAcc)
                  end,
                  StateC,
                  PacketsToResend),

            ReactionsList = [StopWaitingFrameReactions | ResendReactionsList],
            Reactions = lists:flatten(ReactionsList),
            {Reactions, StateD}
    end.
