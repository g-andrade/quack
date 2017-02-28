-module(quic_instream_window).

-callback new_cb(Args :: [term()]) -> Window :: term().

-callback insert_cb(Window :: term(), ChunkOffset :: non_neg_integer(), Chunk :: iodata())
        -> {ok, NewWindow :: term()} | {error, stale_data | overlapping_data | window_full}.

-callback consume_cb(Window :: term())
        -> {NewWindow :: term(), Result :: term()}.

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([new/2]).
-export([insert/3]).
-export([consume/1]).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(instream_window, {
          callback_module :: module(),
          state :: term()
         }).
-opaque value() :: #instream_window{}.
-export_type([value/0]).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-spec new(CallbackModule :: module(), Args :: [term()]) -> Instream :: value().
new(CallbackModule, Args) ->
    #instream_window{
       callback_module = CallbackModule,
       state = CallbackModule:new_cb(Args) }.

-spec insert(Instream :: value(), ChunkOffset :: non_neg_integer(), Chunk :: iodata())
        -> {ok, NewInstream :: value()} | {error, stale_data | overlapping_data | window_full}.
insert(Instream, ChunkOffset, Chunk) ->
    #instream_window{
       callback_module = CallbackModule,
       state = State } = Instream,

    case CallbackModule:insert_cb(State, ChunkOffset, Chunk) of
        {ok, NewState} ->
            {ok, Instream#instream_window{ state = NewState }};
        {error, _} = Error ->
            Error
    end.

-spec consume(Instream :: value()) -> {NewInstream :: value(), Result :: term()}.
consume(Instream) ->
    #instream_window{
       callback_module = CallbackModule,
       state = State } = Instream,

    {NewState, Result} = CallbackModule:consume_cb(State),
    NewInstream = Instream#instream_window{ state = NewState },
    {NewInstream, Result}.
