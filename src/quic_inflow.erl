-module(quic_inflow).

-include("quic_frame.hrl").
-include("quic_packet.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([initial_state/0]).
-export([on_receive_packet/2]).
-export([on_receive_stop_waiting/2]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          % @TODO: we need a more performant data structure for this,
          % otherwise out-of-order packets will kill performance
          inbound_packet_blocks :: [inbound_packet_block()]
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
%% API Function Exports
%% ------------------------------------------------------------------

-spec initial_state() -> state().
initial_state() ->
    #state{
       inbound_packet_blocks = []
      }.

-spec on_receive_packet(regular_packet(), state()) -> [quic_connection:inflow_reaction()].
on_receive_packet(#regular_packet{ packet_number = PacketNumber } = Packet,
                  #state{ inbound_packet_blocks = InboundPacketBlocks } = State) ->
    case put_in_inbound_blocks(PacketNumber, InboundPacketBlocks) of
        repeated ->
            lager:debug("ignoring repeated packet with number ~p", [PacketNumber]),
            [];
        {OrderCategory, NewInboundPacketBlocks} ->
            lager:debug("accepting packet with number ~p (~p)",
                        [PacketNumber, OrderCategory]),
            NewState = State#state{ inbound_packet_blocks = NewInboundPacketBlocks },
            AckFrame = generate_ack_frame(NewState#state.inbound_packet_blocks),
            [{change_state, NewState},
             {send_frame, AckFrame},
             {handle_received_packet, Packet}]
    end.

on_receive_stop_waiting(StopWaitingFrame, State) ->
    StopWaitingPacketNumber = StopWaitingFrame#stop_waiting_frame.least_unacked_packet_number,
    InboundPacketBlocks = State#state.inbound_packet_blocks,
    NewInboundPacketBlocks =
        lists:dropwhile(
          fun (#inbound_packet_block{ largest_packet_number = LargestPacketNumber }) ->
                  LargestPacketNumber < StopWaitingPacketNumber
          end,
          InboundPacketBlocks),
    NewState = State#state{ inbound_packet_blocks = NewInboundPacketBlocks },
    [{change_state, NewState}].

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

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
