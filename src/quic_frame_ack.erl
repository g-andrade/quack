-module(quic_frame_ack).

-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([decode/4]).
-export([encode/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

decode(Data, MultipleAckRangesBit, LargestReceivedEncoding, AckBlockEncoding) ->
    {ChunkA, LargestReceived} = quic_proto_varint:decode_u48(Data, LargestReceivedEncoding),
    <<EncodedLargestReceivedDeltaTime:2/binary, ChunkB/binary>> = ChunkA,
    LargestReceivedDeltaTime = quic_proto_f16:decode(EncodedLargestReceivedDeltaTime),
    {ChunkC, AckBlocks} = decode_blocks(ChunkB, MultipleAckRangesBit, AckBlockEncoding),
    {RemainingData, PacketTimestamps} = decode_packet_timestamps(ChunkC, LargestReceived),

    {RemainingData,
     #ack_frame{ largest_received = LargestReceived,
                 largest_received_time_delta = LargestReceivedDeltaTime,
                 received_packet_blocks = AckBlocks,
                 packet_timestamps = PacketTimestamps }}.

encode(#ack_frame{}) ->
    exit(not_supported).

%% ------------------------------------------------------------------
%% Received packet blocks
%% ------------------------------------------------------------------

decode_blocks(Data, 0 = _MultipleAckRangesBit, AckBlockEncoding) ->
    %lager:debug("decoding single ack block"),
    decode_n_blocks(Data, AckBlockEncoding, 1, 1, []);
decode_blocks(Data, 1 = _MultipleAckRangesBit, AckBlockEncoding) ->
    <<NumBlocksMinus1:8, RemainingData/binary>> = Data,
    NumBlocks = NumBlocksMinus1 + 1,
    %lager:debug("decoding ~p ack blocks", [NumBlocks]),
    decode_n_blocks(RemainingData, AckBlockEncoding, NumBlocks, NumBlocks, []).


decode_n_blocks(Data, _AckBlockEncoding, RemainingNumBlocks, _TotalNumBlocks, BlocksAcc)
  when RemainingNumBlocks < 1->
    % no more blocks
    %lager:debug("finished decoding ~p ack blocks", [TotalNumBlocks]),
    {Data, lists:reverse(BlocksAcc)};

decode_n_blocks(Data, AckBlockEncoding, RemainingNumBlocks, TotalNumBlocks, BlocksAcc)
  when RemainingNumBlocks =:= TotalNumBlocks ->
    % first
    {RemainingData, AckBlockDelta} = quic_proto_varint:decode_u48(Data, AckBlockEncoding),
    %lager:debug("decoded ~p/~p ack block: ~p", [TotalNumBlocks - RemainingNumBlocks + 1,
    %                                            TotalNumBlocks,
    %                                            AckBlockDelta]),

    Block =
        #ack_received_packet_block{
           gap_from_prev_block = 0,
           ack_block_length = AckBlockDelta },

    NewBlocksAcc = [Block | BlocksAcc],
    decode_n_blocks(RemainingData, AckBlockEncoding, RemainingNumBlocks - 1,
                              TotalNumBlocks, NewBlocksAcc);

decode_n_blocks(Data, AckBlockEncoding, RemainingNumBlocks, TotalNumBlocks, BlocksAcc) ->
    <<AckBlockGap:8, ChunkA/binary>> = Data,
    {ChunkB, AckBlockDelta} = quic_proto_varint:decode_u48(ChunkA, AckBlockEncoding),
    %lager:debug("decoded ~p/~p ack block: ~p (gap ~p)", [TotalNumBlocks - RemainingNumBlocks + 1,
    %                                                     TotalNumBlocks,
    %                                                     AckBlockDelta,
    %                                                     AckBlockGap]),
    Block =
        #ack_received_packet_block{
           gap_from_prev_block = AckBlockGap,
           ack_block_length = AckBlockDelta },

    NewBlocksAcc = [Block | BlocksAcc],
    decode_n_blocks(ChunkB, AckBlockEncoding, RemainingNumBlocks - 1,
                              TotalNumBlocks, NewBlocksAcc).

%% ------------------------------------------------------------------
%% Timestamps
%% ------------------------------------------------------------------

decode_packet_timestamps(Data, LargestReceived) ->
    <<NumEntries:8,
      ChunkA/binary>> = Data,
    %lager:debug("decoding ~p ack timestamps", [NumEntries]),
    decode_packet_timestamp_entries(ChunkA, NumEntries, NumEntries, LargestReceived, 0, []).


decode_packet_timestamp_entries(Data, RemainingNumEntries, _TotalNumEntries,
                                _LargestReceived, _BaseTimeSinceLargestReceived, Acc)
  when RemainingNumEntries < 1 ->
    % no more entries
    {Data, lists:reverse(Acc)};

decode_packet_timestamp_entries(Data, RemainingNumEntries, TotalNumEntries,
                                LargestReceived, 0 = _BaseTimeSinceLargestReceived, Acc)
  when RemainingNumEntries =:= TotalNumEntries ->
    % first
    <<DeltaLargestReceived:8,
      TimeSinceLargestReceived:4/little-unsigned-integer-unit:8,
      ChunkA/binary>> = Data,
    %lager:debug("decoded first ack timestamp: ~p/~p", [DeltaLargestReceived, TimeSinceLargestReceived]),

    Entry = #ack_frame_packet_timestamp{
               packet_number = LargestReceived + DeltaLargestReceived,
               largest_received_time_delta = TimeSinceLargestReceived
              },
    NewAcc = [Entry | Acc],
    decode_packet_timestamp_entries(ChunkA, RemainingNumEntries - 1, TotalNumEntries,
                                    LargestReceived, TimeSinceLargestReceived, NewAcc);

decode_packet_timestamp_entries(Data, RemainingNumEntries, TotalNumEntries,
                                LargestReceived, BaseTimeSinceLargestReceived, Acc) ->
    <<DeltaLargestReceived:8,
      EncodedTimeSincePreviousTimestamp:2/binary,
      ChunkA/binary>> = Data,
    TimeSincePreviousTimestamp = quic_proto_f16:decode(EncodedTimeSincePreviousTimestamp),
    TimeSinceLargestReceived = BaseTimeSinceLargestReceived + TimeSincePreviousTimestamp,

    %lager:debug("decoded ack timestamp: ~p/~p", [DeltaLargestReceived, TimeSinceLargestReceived]),

    Entry = #ack_frame_packet_timestamp{
               packet_number = LargestReceived + DeltaLargestReceived,
               largest_received_time_delta = TimeSinceLargestReceived
              },
    NewAcc = [Entry | Acc],
    decode_packet_timestamp_entries(ChunkA, RemainingNumEntries - 1, TotalNumEntries,
                                    LargestReceived, BaseTimeSinceLargestReceived, NewAcc).
