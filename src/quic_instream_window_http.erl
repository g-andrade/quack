-module(quic_instream_window_http).
-behaviour(quic_instream_window).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([new/1]).

%% ------------------------------------------------------------------
%% quic_instream_window Function Exports
%% ------------------------------------------------------------------

-export([new_cb/1]).
-export([insert_cb/3]).
-export([consume_cb/1]).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(http_instream_window, {
          data_instream_window :: quic_instream_window:value(),
          undecoded_buffer :: binary()
         }).
-opaque value() :: #http_instream_window{}.
-export_type([value/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec new(DataInstream :: quic_instream_window:value()) -> quic_instream_window:value().
new(DataInstream) ->
    quic_instream_window:new(?MODULE, [DataInstream]).

%% ------------------------------------------------------------------
%% quic_instream_window Function Definitions
%% ------------------------------------------------------------------

-spec new_cb(Args :: [DataInstream :: quic_instream_window:value()]) -> value().
new_cb([DataInstream]) ->
    #http_instream_window{
       data_instream_window = DataInstream,
       undecoded_buffer = <<>>
      }.

-spec insert_cb(HttpInstream :: value(), ChunkOffset :: non_neg_integer(), Chunk :: iodata())
        -> {ok, NewHttpInstream :: value()} | {error, stale_data | overlapping_data | window_full}.
insert_cb(#http_instream_window{ data_instream_window = DataInstream } = HttpInstream, ChunkOffset, Chunk) ->
    case quic_instream_window:insert(DataInstream, ChunkOffset, Chunk) of
        {ok, NewDataInstream} ->
            {ok, HttpInstream#http_instream_window{ data_instream_window = NewDataInstream }};
        {error, _} = Error ->
            Error
    end.

-spec consume_cb(HttpInstream :: value())
        -> {NewHttpInstream :: value(), HttpFrames :: [quic_http:http()]}.
consume_cb(#http_instream_window{ data_instream_window = DataInstream } = HttpInstream) ->
    {NewDataInstream, Data} = quic_instream_window:consume(DataInstream),
    case iolist_size(Data) > 0 of
        false -> {HttpInstream#http_instream_window{ data_instream_window = NewDataInstream }, []};
        true ->
            UndecodedBuffer = HttpInstream#http_instream_window.undecoded_buffer,
            UndecodedBufferB = iolist_to_binary([UndecodedBuffer, Data]),
            {UndecodedBufferC, HttpFrames} = consume_all_frames(UndecodedBufferB),
            NewHttpInstream = HttpInstream#http_instream_window{
                                data_instream_window = NewDataInstream,
                                undecoded_buffer = UndecodedBufferC },
            {NewHttpInstream, HttpFrames}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

consume_all_frames(UndecodedBuffer) ->
    consume_all_frames(UndecodedBuffer, []).

consume_all_frames(UndecodedBuffer, RevAcc) ->
    case h2_frame:recv(UndecodedBuffer) of
        {ok, Frame, NewUndecodedBuffer} ->
            consume_all_frames(NewUndecodedBuffer, [Frame | RevAcc]);
        {not_enough_header, NewUndecodedBuffer} ->
            {NewUndecodedBuffer, lists:reverse(RevAcc)};
        {not_enough_payload, FrameHeader, NewUndecodedBuffer} ->
            % TODO common, the following is just lazy;
            % cache decoded headers for incomplete frames properly
            NewUndecodedBuffer2 =
                [h2_frame:header_to_binary(FrameHeader),
                 NewUndecodedBuffer],
            {NewUndecodedBuffer2, lists:reverse(RevAcc)}
    end.
