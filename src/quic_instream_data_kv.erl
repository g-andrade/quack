-module(quic_instream_data_kv).
-behaviour(quic_instream).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([new/1]).

%% ------------------------------------------------------------------
%% quic_instream Function Exports
%% ------------------------------------------------------------------

-export([new_cb/1]).
-export([insert_cb/3]).
-export([consume_cb/1]).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(data_kv_instream, {
          data_instream :: quic_instream:value(),
          undecoded_buffer :: binary()
         }).
-opaque value() :: #data_kv_instream{}.
-export_type([value/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec new(DataInstream :: quic_instream:value()) -> quic_instream:value().
new(DataInstream) ->
    quic_instream:new(?MODULE, [DataInstream]).

%% ------------------------------------------------------------------
%% quic_instream Function Definitions
%% ------------------------------------------------------------------

-spec new_cb(Args :: [DataInstream :: quic_instream:value()]) -> value().
new_cb([DataInstream]) ->
    #data_kv_instream{
       data_instream = DataInstream,
       undecoded_buffer = <<>>
      }.

-spec insert_cb(DataKvInstream :: value(), ChunkOffset :: non_neg_integer(), Chunk :: iodata())
        -> {ok, NewDataKvInstream :: value()} | {error, stale_data | overlapping_data | window_full}.
insert_cb(#data_kv_instream{ data_instream = DataInstream } = DataKvInstream, ChunkOffset, Chunk) ->
    case quic_instream:insert(DataInstream, ChunkOffset, Chunk) of
        {ok, NewDataInstream} ->
            {ok, DataKvInstream#data_kv_instream{ data_instream = NewDataInstream }};
        {error, _} = Error ->
            Error
    end.

-spec consume_cb(DataKvInstream :: value()) 
        -> {NewDataKvInstream :: value(), DataKvs :: [quic_data_kv:data_kv()]}.
consume_cb(#data_kv_instream{ data_instream = DataInstream } = DataKvInstream) ->
    {NewDataInstream, {DataSize, Data}} = quic_instream:consume(DataInstream),
    case DataSize > 0 of
        false -> {DataKvInstream#data_kv_instream{ data_instream = NewDataInstream }, []};
        true ->
            UndecodedBuffer = DataKvInstream#data_kv_instream.undecoded_buffer,
            UndecodedBufferB = iolist_to_binary([UndecodedBuffer, Data]),
            {UndecodedBufferC, DataKvs} = consume_all_kvs(UndecodedBufferB),
            NewDataKvInstream = DataKvInstream#data_kv_instream{ data_instream = NewDataInstream,
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
