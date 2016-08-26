-module(quic_frame).

-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([append_padding_to_encoded_frames/3]).
-export([decode_frames/2]).
-export([encode_frames/2]).

%% ------------------------------------------------------------------
%% Padding
%% ------------------------------------------------------------------

append_padding_to_encoded_frames(EncodedFrames, MissingSize, PacketNumberEncoding) when MissingSize > 0 ->
    [EncodedFrames, encode_frame(#padding_frame{ size = MissingSize - 1 }, PacketNumberEncoding)].

%% ------------------------------------------------------------------
%% Frame sequence decoding
%% ------------------------------------------------------------------

decode_frames(<<>>, _PacketNumberEncoding) ->
    [];
decode_frames(<<1:1,
                FinBit:1,
                DataLengthBit:1,
                OffsetHeaderEncoding:3,
                StreamIdEncoding:2,
                Data/binary>>,
              PacketNumberEncoding) ->
    % Stream frame (special)
    {RemainingData, Frame} = decode_stream_frame(Data, FinBit, DataLengthBit,
                                                 OffsetHeaderEncoding,
                                                 StreamIdEncoding),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<0:1,
                1:1,
                MultipleAckRangesBit:1,
                _:1, % unused
                LargestAckedEncoding:2,
                AckBlockEncoding:2,
                Data/binary>>,
              PacketNumberEncoding) ->
    % ACK frame (special)
    {RemainingData, Frame} = decode_ack_frame(Data, MultipleAckRangesBit,
                                              LargestAckedEncoding,
                                              AckBlockEncoding),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
%decode_frames(<<0:2,
%                1:1,
%                _:5, % unused,
%                _/binary>>) ->
%    % Congestion feedback (special - unspecified yet)
%    exit({unspecified, congestion_feedback});
decode_frames(<<2#00000000:8, Data/binary>>, PacketNumberEncoding) ->
    % Padding frame
    {RemainingData, Frame} = decode_padding_frame(Data),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<2#00000001:8, Data/binary>>, PacketNumberEncoding) ->
    % Reset stream frame
    {RemainingData, Frame} = decode_reset_stream_frame(Data),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<2#00000010:8, Data/binary>>, PacketNumberEncoding) ->
    % Connection close frame
    {RemainingData, Frame} = decode_connection_close_frame(Data),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<2#00000011:8, Data/binary>>, PacketNumberEncoding) ->
    % Go away frame
    {RemainingData, Frame} = decode_go_away_frame(Data),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<2#00000100:8, Data/binary>>, PacketNumberEncoding) ->
    % Window update frame
    {RemainingData, Frame} = decode_window_update_frame(Data),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<2#00000101:8, Data/binary>>, PacketNumberEncoding) ->
    % Blocked frame
    {RemainingData, Frame} = decode_blocked_frame(Data),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<2#00000110:8, Data/binary>>, PacketNumberEncoding) ->
    % Stop waiting frame
    {RemainingData, Frame} = decode_stop_waiting_frame(Data, PacketNumberEncoding),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)];
decode_frames(<<2#00000111:8, Data/binary>>, PacketNumberEncoding) ->
    % Ping frame
    {RemainingData, Frame} = decode_ping_frame(Data),
    [Frame | decode_frames(RemainingData, PacketNumberEncoding)].

%% ------------------------------------------------------------------
%% Frame sequence encoding
%% ------------------------------------------------------------------

encode_frames(Frames, PacketNumberEncoding) ->
    [encode_frame(Frame, PacketNumberEncoding) || Frame <- Frames].

encode_frame(Frame, _PacketNumberEncoding) when is_record(Frame, stream_frame);
                                               is_record(Frame, stream_fin_frame) ->
    {Data, FinBit, DataLengthBit, OffsetHeaderEncoding, StreamIdEncoding} =
        encode_stream_frame(Frame),
    [<<1:1,
       FinBit:1,
       DataLengthBit:1,
       OffsetHeaderEncoding:3,
       StreamIdEncoding:2>>,
     Data];
encode_frame(#ack_frame{} = Frame, _PacketNumberEncoding) ->
    {Data, MultipleAckRangesBit, LargestAckedEncoding, AckBlockEncoding} =
        encode_ack_frame(Frame),
    [<<0:1,
       1:1,
       MultipleAckRangesBit:1,
       0:1, % unused
       LargestAckedEncoding:2,
       AckBlockEncoding:2>>,
     Data];
encode_frame(#padding_frame{} = Frame, _PacketNumberEncoding) ->
    [2#00000000, encode_padding_frame(Frame)];
encode_frame(#reset_stream_frame{} = Frame, _PacketNumberEncoding) ->
    [2#00000001, encode_reset_stream_frame(Frame)];
encode_frame(#connection_close_frame{} = Frame, _PacketNumberEncoding) ->
    [2#00000010, encode_connection_close_frame(Frame)];
encode_frame(#go_away_frame{} = Frame, _PacketNumberEncoding) ->
    [2#00000011, encode_go_away_frame(Frame)];
encode_frame(#window_update_frame{} = Frame, _PacketNumberEncoding) ->
    [2#00000100, encode_window_update_frame(Frame)];
encode_frame(#blocked_frame{} = Frame, _PacketNumberEncoding) ->
    [2#00000101, encode_blocked_frame(Frame)];
encode_frame(#stop_waiting_frame{} = Frame, PacketNumberEncoding) ->
    [2#00000110, encode_stop_waiting_frame(Frame, PacketNumberEncoding)];
encode_frame(#ping_frame{} = Frame, _PacketNumberEncoding) ->
    [2#00000111, encode_ping_frame(Frame)].

%% ------------------------------------------------------------------
%% Stream frame handling
%% ------------------------------------------------------------------

decode_stream_frame(Data, FinBit, DataLengthBit, OffsetHeaderEncoding, StreamIdEncoding) ->
    {ChunkA, StreamId} = quic_proto_varint:decode_u32(Data, StreamIdEncoding),
    {ChunkB, Offset} = quic_proto_varint:decode_u64(ChunkA, OffsetHeaderEncoding),
    {ChunkC, DataPayloadLength} = decode_stream_frame_data_length(ChunkB, FinBit, DataLengthBit),
    <<DataPayload:DataPayloadLength/binary, RemainingData/binary>> = ChunkC,
    {RemainingData,
     case FinBit of
         1 -> #stream_fin_frame{ stream_id = StreamId };
         0 -> #stream_frame{ stream_id = StreamId,
                             offset = Offset,
                             data_payload = DataPayload }
     end}.

decode_stream_frame_data_length(<<DataLength:2/little-unsigned-integer-unit:8,
                                  RemainingData/binary>>,
                                FinBit, DataLengthBit)
  when (FinBit =:= 0 andalso DataLengthBit =:= 1 andalso DataLength > 1);
       (FinBit =:= 1 andalso DataLengthBit =:= 1 andalso DataLength =:= 0) ->
    {RemainingData, DataLength};
decode_stream_frame_data_length(<<RemainingData/binary>>,
                                FinBit, DataLengthBit)
  when FinBit =:= 0, DataLengthBit =:= 0 ->
    % stream frame extends to the end of the packet
    {RemainingData, byte_size(RemainingData)}.

encode_stream_frame(#stream_fin_frame{ stream_id = StreamId }) ->
    FinBit = 1,
    DataLengthBit = 0,
    {EncodedStreamId, StreamIdEncoding} = quic_proto_varint:encode_u32(StreamId),
    {EncodedOffset, OffsetHeaderEncoding} = quic_proto_varint:encode_u64(0),
    {[EncodedStreamId, EncodedOffset],
     FinBit, DataLengthBit, OffsetHeaderEncoding, StreamIdEncoding};
encode_stream_frame(#stream_frame{ stream_id = StreamId,
                                   offset = Offset,
                                   data_payload = DataPayload }) ->
    DataPayloadLength = iolist_size(DataPayload),
    FinBit = 0,
    DataLengthBit = 1,
    {EncodedStreamId, StreamIdEncoding} = quic_proto_varint:encode_u32(StreamId),
    {EncodedOffset, OffsetHeaderEncoding} = quic_proto_varint:encode_u64(Offset),
    EncodedDataPayloadLength = <<DataPayloadLength:2/little-unsigned-integer-unit:8>>,
    {[EncodedStreamId, EncodedOffset, EncodedDataPayloadLength, DataPayload],
     FinBit, DataLengthBit, OffsetHeaderEncoding, StreamIdEncoding}.

%% ------------------------------------------------------------------
%% Ack frame handling
%% ------------------------------------------------------------------

decode_ack_frame(Data, MultipleAckRangesBit, LargestAckedEncoding, AckBlockEncoding) ->
    {ChunkA, _LargestAcked} = quic_proto_varint:decode_u48(Data, LargestAckedEncoding),
    <<_LargestAckedDeltaTime:2/binary, ChunkB/binary>> = ChunkA,
    {ChunkC, _AckBlocks} = decode_ack_frame_blocks(ChunkB, MultipleAckRangesBit, AckBlockEncoding),
    {RemainingData, PacketTimestamps} = decode_ack_frame_packet_timestamps(ChunkC),
    %lager:debug("~p bytes left", [byte_size(RemainingData)]),
    {RemainingData,
     #ack_frame{ largest_acked = unhandled,
                 largest_acked_delta_time = unhandled,
                 packet_timestamps = PacketTimestamps }}.

decode_ack_frame_blocks(Data, 0 = _MultipleAckRangesBit, AckBlockEncoding) ->
    %lager:debug("decoding single ack block"),
    decode_ack_frame_n_blocks(Data, AckBlockEncoding, 1, 1, []);
decode_ack_frame_blocks(Data, 1 = _MultipleAckRangesBit, AckBlockEncoding) ->
    <<NumBlocksMinus1:8, RemainingData/binary>> = Data,
    NumBlocks = NumBlocksMinus1 + 1,
    %lager:debug("decoding ~p ack blocks", [NumBlocks]),
    decode_ack_frame_n_blocks(RemainingData, AckBlockEncoding, NumBlocks, NumBlocks, []).

decode_ack_frame_n_blocks(Data, _AckBlockEncoding, RemainingNumBlocks, _TotalNumBlocks, BlocksAcc)
  when RemainingNumBlocks < 1->
    % no more blocks
    %lager:debug("finished decoding ~p ack blocks", [TotalNumBlocks]),
    {Data, lists:reverse(BlocksAcc)};
decode_ack_frame_n_blocks(Data, AckBlockEncoding, RemainingNumBlocks, TotalNumBlocks, BlocksAcc)
  when RemainingNumBlocks =:= TotalNumBlocks ->
    % first
    {RemainingData, _AckBlockDelta} = quic_proto_varint:decode_u48(Data, AckBlockEncoding),
    %lager:debug("decoded ~p/~p ack block: ~p", [TotalNumBlocks - RemainingNumBlocks + 1,
    %                                            TotalNumBlocks,
    %                                            AckBlockDelta]),
    decode_ack_frame_n_blocks(RemainingData, AckBlockEncoding, RemainingNumBlocks - 1,
                              TotalNumBlocks, BlocksAcc);
decode_ack_frame_n_blocks(Data, AckBlockEncoding, RemainingNumBlocks, TotalNumBlocks, BlocksAcc) ->
    {ChunkA, _AckBlockDelta} = quic_proto_varint:decode_u48(Data, AckBlockEncoding),
    <<_AckBlockGap:8, ChunkB/binary>> = ChunkA,
    %lager:debug("decoded ~p/~p ack block: ~p (gap ~p)", [TotalNumBlocks - RemainingNumBlocks + 1,
    %                                                     TotalNumBlocks,
    %                                                     AckBlockDelta,
    %                                                    AckBlockGap]),
    decode_ack_frame_n_blocks(ChunkB, AckBlockEncoding, RemainingNumBlocks - 1,
                              TotalNumBlocks, BlocksAcc).

decode_ack_frame_packet_timestamps(Data) ->
    <<NumEntries:8,
      ChunkA/binary>> = Data,
    %lager:debug("decoding ~p ack timestamps", [NumEntries]),
    {RemainingData, _Unhandled} = decode_ack_frame_packet_timestamp_entries(ChunkA, NumEntries, NumEntries, []),
    {RemainingData, unhandled}.

decode_ack_frame_packet_timestamp_entries(Data, RemainingNumEntries, _TotalNumEntries, Acc)
  when RemainingNumEntries < 1 ->
    % no more entries
    {Data, lists:reverse(Acc)};
decode_ack_frame_packet_timestamp_entries(Data, RemainingNumEntries, TotalNumEntries, Acc)
  when RemainingNumEntries =:= TotalNumEntries ->
    % first
    <<_DeltaLargestAcked:8,
      _TimeSincePreviousTimestamp:4/little-unsigned-integer-unit:8,
      ChunkA/binary>> = Data,
    %lager:debug("decoded first ack timestamp: ~p/~p", [DeltaLargestAcked, TimeSincePreviousTimestamp]),
    decode_ack_frame_packet_timestamp_entries(ChunkA, RemainingNumEntries - 1, TotalNumEntries, Acc);
decode_ack_frame_packet_timestamp_entries(Data, RemainingNumEntries, TotalNumEntries, Acc) ->
    <<_DeltaLargestAcked:8,
      _TimeSincePreviousTimestamp:2/binary, % @TODO: 16 bit custom floating point
      ChunkA/binary>> = Data,
    %lager:debug("decoded ack timestamp: ~p/~p", [DeltaLargestAcked, TimeSincePreviousTimestamp]),
    decode_ack_frame_packet_timestamp_entries(ChunkA, RemainingNumEntries - 1, TotalNumEntries, Acc).

encode_ack_frame(#ack_frame{}) ->
    exit(not_supported).

%% ------------------------------------------------------------------
%% Padding frame handling
%% ------------------------------------------------------------------

decode_padding_frame(PaddingData) ->
    {<<>>, #padding_frame{ size = byte_size(PaddingData) }}.

encode_padding_frame(#padding_frame{ size = Size }) ->
    [0 || _ <- lists:seq(1, Size)].

%% ------------------------------------------------------------------
%% Reset stream frame handling
%% ------------------------------------------------------------------

decode_reset_stream_frame(<<StreamId:4/little-unsigned-integer-unit:8,
                            ByteOffset:8/little-unsigned-integer-unit:8,
                            ErrorCode:4/binary,
                            RemainingData/binary>>) ->
    {RemainingData,
     #reset_stream_frame{ stream_id = StreamId,
                          byte_offset = ByteOffset,
                          error_code = ErrorCode }}.

encode_reset_stream_frame(#reset_stream_frame{ stream_id = StreamId,
                                               byte_offset = ByteOffset,
                                               error_code = ErrorCode }) ->
    <<StreamId:4/little-unsigned-integer-unit:8,
      ByteOffset:8/little-unsigned-integer-unit:8,
      ErrorCode:4/binary>>.

%% ------------------------------------------------------------------
%% Connection close frame handling
%% ------------------------------------------------------------------

decode_connection_close_frame(<<ErrorCode:4/binary,
                                ReasonPhraseLength:2/little-unsigned-integer-unit:8,
                                ReasonPhrase:ReasonPhraseLength/binary,
                                RemainingData/binary>>) ->
    {RemainingData,
     #connection_close_frame{ error_code = ErrorCode,
                              reason_phrase = ReasonPhrase }}.

encode_connection_close_frame(#connection_close_frame{ error_code = ErrorCode,
                                                       reason_phrase = ReasonPhrase }) ->
    ReasonPhraseLength = byte_size(ReasonPhrase),
    <<ErrorCode:4/binary,
      ReasonPhraseLength:2/little-unsigned-integer-unit:8,
      ReasonPhrase/binary>>.

%% ------------------------------------------------------------------
%% Go away frame handling
%% ------------------------------------------------------------------

decode_go_away_frame(<<ErrorCode:4/binary,
                       LastGoodStreamId:4/little-unsigned-integer-unit:8,
                       ReasonPhraseLength:2/little-unsigned-integer-unit:8,
                       ReasonPhrase:ReasonPhraseLength/binary,
                       RemainingData/binary>>) ->
    {RemainingData,
     #go_away_frame{ error_code = ErrorCode,
                     last_good_stream_id = LastGoodStreamId,
                     reason_phrase = ReasonPhrase }}.

encode_go_away_frame(#go_away_frame{ error_code = ErrorCode,
                                     last_good_stream_id = LastGoodStreamId,
                                     reason_phrase = ReasonPhrase }) ->
    ReasonPhraseLength = byte_size(ReasonPhrase),
    <<ErrorCode:4/binary,
      LastGoodStreamId:4/little-unsigned-integer-unit:8,
      ReasonPhraseLength:2/little-unsigned-integer-unit:8,
      ReasonPhrase/binary>>.

%% ------------------------------------------------------------------
%% Window update frame handling
%% ------------------------------------------------------------------

decode_window_update_frame(<<StreamId:4/little-unsigned-integer-unit:8,
                             ByteOffset:8/little-unsigned-integer-unit:8,
                             RemainingData/binary>>) ->
    {RemainingData,
     #window_update_frame{ stream_id = StreamId,
                           byte_offset = ByteOffset }}.

encode_window_update_frame(#window_update_frame{ stream_id = StreamId,
                                                 byte_offset = ByteOffset }) ->
    <<StreamId:4/little-unsigned-integer-unit:8,
      ByteOffset:8/little-unsigned-integer-unit:8>>.

%% ------------------------------------------------------------------
%% Blocked frame handling
%% ------------------------------------------------------------------

decode_blocked_frame(<<StreamId:4/little-unsigned-integer-unit:8,
                       RemainingData/binary>>) ->
    {RemainingData,
     #blocked_frame{ stream_id = StreamId }}.

encode_blocked_frame(#blocked_frame{ stream_id = StreamId }) ->
    <<StreamId:4/little-unsigned-integer-unit:8>>.

%% ------------------------------------------------------------------
%% Stop waiting frame handling
%% ------------------------------------------------------------------

decode_stop_waiting_frame(Data, PacketNumberEncoding) ->
    {RemainingData, LeastUnackedDelta} = quic_proto_varint:decode_u48(Data, PacketNumberEncoding),
    {RemainingData,
     #stop_waiting_frame{ least_unacked_delta = LeastUnackedDelta }}.

encode_stop_waiting_frame(#stop_waiting_frame{ least_unacked_delta = LeastUnackedDelta },
                          PacketNumberEncoding) ->
    quic_proto_varint:encode_u48(LeastUnackedDelta, PacketNumberEncoding).

%% ------------------------------------------------------------------
%% Ping frame handling
%% ------------------------------------------------------------------

decode_ping_frame(Data) ->
    {Data, #ping_frame{}}.

encode_ping_frame(#ping_frame{}) ->
    "".
