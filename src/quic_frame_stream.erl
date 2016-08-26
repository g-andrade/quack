-module(quic_frame_stream).

-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([decode/5]).
-export([encode/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

decode(Data, FinBit, DataLengthBit, OffsetHeaderEncoding, StreamIdEncoding) ->
    {ChunkA, StreamId} = quic_proto_varint:decode_u32(Data, StreamIdEncoding),
    {ChunkB, Offset} = quic_proto_varint:decode_u64(ChunkA, OffsetHeaderEncoding),
    {ChunkC, DataPayloadLength} = decode_data_length(ChunkB, FinBit, DataLengthBit),
    <<DataPayload:DataPayloadLength/binary, RemainingData/binary>> = ChunkC,
    {RemainingData,
     case FinBit of
         1 -> #stream_fin_frame{ stream_id = StreamId };
         0 -> #stream_frame{ stream_id = StreamId,
                             offset = Offset,
                             data_payload = DataPayload }
     end}.

encode(#stream_fin_frame{ stream_id = StreamId }) ->
    FinBit = 1,
    DataLengthBit = 0,
    {EncodedStreamId, StreamIdEncoding} = quic_proto_varint:encode_u32(StreamId),
    {EncodedOffset, OffsetHeaderEncoding} = quic_proto_varint:encode_u64(0),
    {[EncodedStreamId, EncodedOffset],
     FinBit, DataLengthBit, OffsetHeaderEncoding, StreamIdEncoding};
encode(#stream_frame{ stream_id = StreamId,
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
%% Internal Function Definitions
%% ------------------------------------------------------------------

decode_data_length(<<DataLength:2/little-unsigned-integer-unit:8,
                     RemainingData/binary>>,
                   FinBit, DataLengthBit)
  when (FinBit =:= 0 andalso DataLengthBit =:= 1 andalso DataLength > 1);
       (FinBit =:= 1 andalso DataLengthBit =:= 1 andalso DataLength =:= 0) ->
    {RemainingData, DataLength};
decode_data_length(<<RemainingData/binary>>,
                   FinBit, DataLengthBit)
  when FinBit =:= 0, DataLengthBit =:= 0 ->
    % stream frame extends to the end of the packet
    {RemainingData, byte_size(RemainingData)}.

