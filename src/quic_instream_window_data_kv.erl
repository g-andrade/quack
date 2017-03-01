-module(quic_instream_window_data_kv).
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

-record(data_kv_instream_window, {
          data_instream_window :: quic_instream_window:value(),
          undecoded_buffer :: binary()
         }).
-opaque value() :: #data_kv_instream_window{}.
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
    #data_kv_instream_window{
       data_instream_window = DataInstream,
       undecoded_buffer = <<>>
      }.

-spec insert_cb(DataKvInstream :: value(), ChunkOffset :: non_neg_integer(), Chunk :: iodata())
        -> {ok, NewDataKvInstream :: value()} | {error, stale_data | overlapping_data | window_full}.
insert_cb(#data_kv_instream_window{ data_instream_window = DataInstream } = DataKvInstream, ChunkOffset, Chunk) ->
    case quic_instream_window:insert(DataInstream, ChunkOffset, Chunk) of
        {ok, NewDataInstream} ->
            {ok, DataKvInstream#data_kv_instream_window{ data_instream_window = NewDataInstream }};
        {error, _} = Error ->
            Error
    end.

-spec consume_cb(DataKvInstream :: value()) 
        -> {NewDataKvInstream :: value(), DataKvs :: [quic_data_kv:data_kv()]}.
consume_cb(#data_kv_instream_window{ data_instream_window = DataInstream } = DataKvInstream) ->
    {NewDataInstream, Data} = quic_instream_window:consume(DataInstream),
    case iolist_size(Data) > 0 of
        false -> {DataKvInstream#data_kv_instream_window{ data_instream_window = NewDataInstream }, []};
        true ->
            UndecodedBuffer = DataKvInstream#data_kv_instream_window.undecoded_buffer,
            UndecodedBufferB = iolist_to_binary([UndecodedBuffer, Data]),
            {UndecodedBufferC, DataKvs} = consume_all_kvs(UndecodedBufferB),
            NewDataKvInstream = DataKvInstream#data_kv_instream_window{ data_instream_window = NewDataInstream,
                                       undecoded_buffer = UndecodedBufferC },
            {NewDataKvInstream, DataKvs}
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

consume_all_kvs(UndecodedBuffer) ->
    consume_all_kvs(UndecodedBuffer, []).

consume_all_kvs(UndecodedBuffer, RevAcc) ->
    case quic_data_kv:decode(UndecodedBuffer) of
        incomplete ->
            {UndecodedBuffer, lists:reverse(RevAcc)};
        {DataKv, NewUndecodedBuffer} ->
            consume_all_kvs(NewUndecodedBuffer, [DataKv | RevAcc])
    end.
