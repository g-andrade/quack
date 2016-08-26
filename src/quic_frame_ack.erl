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

decode(Data, MultipleAckRangesBit, LargestAckedEncoding, AckBlockEncoding) ->
    {ChunkA, LargestAcked} = quic_proto_varint:decode_u48(Data, LargestAckedEncoding),
    <<EncodedLargestAckedDeltaTime:2/binary, ChunkB/binary>> = ChunkA,
    LargestAckedDeltaTime = quic_proto_f16:decode(EncodedLargestAckedDeltaTime),
    {ChunkC, _AckBlocks} = decode_blocks(ChunkB, MultipleAckRangesBit, AckBlockEncoding),
    {RemainingData, PacketTimestamps} = decode_packet_timestamps(ChunkC),
    %lager:debug("~p bytes left", [byte_size(RemainingData)]),
    {RemainingData,
     #ack_frame{ largest_acked = LargestAcked,
                 largest_acked_delta_time = LargestAckedDeltaTime,
                 packet_timestamps = PacketTimestamps }}.

encode(#ack_frame{}) ->
    exit(not_supported).

%% ------------------------------------------------------------------
%% Internal Function Definitions
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
    {RemainingData, _AckBlockDelta} = quic_proto_varint:decode_u48(Data, AckBlockEncoding),
    %lager:debug("decoded ~p/~p ack block: ~p", [TotalNumBlocks - RemainingNumBlocks + 1,
    %                                            TotalNumBlocks,
    %                                            AckBlockDelta]),
    decode_n_blocks(RemainingData, AckBlockEncoding, RemainingNumBlocks - 1,
                              TotalNumBlocks, BlocksAcc);
decode_n_blocks(Data, AckBlockEncoding, RemainingNumBlocks, TotalNumBlocks, BlocksAcc) ->
    {ChunkA, _AckBlockDelta} = quic_proto_varint:decode_u48(Data, AckBlockEncoding),
    <<_AckBlockGap:8, ChunkB/binary>> = ChunkA,
    %lager:debug("decoded ~p/~p ack block: ~p (gap ~p)", [TotalNumBlocks - RemainingNumBlocks + 1,
    %                                                     TotalNumBlocks,
    %                                                     AckBlockDelta,
    %                                                    AckBlockGap]),
    decode_n_blocks(ChunkB, AckBlockEncoding, RemainingNumBlocks - 1,
                              TotalNumBlocks, BlocksAcc).

decode_packet_timestamps(Data) ->
    <<NumEntries:8,
      ChunkA/binary>> = Data,
    %lager:debug("decoding ~p ack timestamps", [NumEntries]),
    {RemainingData, _Unhandled} = decode_packet_timestamp_entries(ChunkA, NumEntries, NumEntries, []),
    {RemainingData, unhandled}.

decode_packet_timestamp_entries(Data, RemainingNumEntries, _TotalNumEntries, Acc)
  when RemainingNumEntries < 1 ->
    % no more entries
    {Data, lists:reverse(Acc)};
decode_packet_timestamp_entries(Data, RemainingNumEntries, TotalNumEntries, Acc)
  when RemainingNumEntries =:= TotalNumEntries ->
    % first
    <<_DeltaLargestAcked:8,
      _TimeSincePreviousTimestamp:4/little-unsigned-integer-unit:8,
      ChunkA/binary>> = Data,
    %lager:debug("decoded first ack timestamp: ~p/~p", [DeltaLargestAcked, TimeSincePreviousTimestamp]),
    decode_packet_timestamp_entries(ChunkA, RemainingNumEntries - 1, TotalNumEntries, Acc);
decode_packet_timestamp_entries(Data, RemainingNumEntries, TotalNumEntries, Acc) ->
    <<_DeltaLargestAcked:8,
      _TimeSincePreviousTimestamp:2/binary, % @TODO: 16 bit custom floating point
      ChunkA/binary>> = Data,
    %lager:debug("decoded ack timestamp: ~p/~p", [DeltaLargestAcked, TimeSincePreviousTimestamp]),
    decode_packet_timestamp_entries(ChunkA, RemainingNumEntries - 1, TotalNumEntries, Acc).
