-module(quic_stream).

-callback on_start_cb(Args :: [term()]) -> {DataPacking :: data_packing(),
                                            CallbackState :: term(),
                                            Reactions :: [reaction()]}.

-callback on_inbound_cb(Value :: term(), CallbackState :: term())
        -> {[reaction()], NewCallbackState :: term()}.

-include("quic_data_kv.hrl").
-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([on_start/3]).
-export([on_inbound_data/3]).
-export([on_outbound_data/2]).
-export([callback_state/1]).
-export([set_callback_state/2]).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          stream_id :: stream_id(),
          data_packing :: data_packing(),
          instream :: quic_instream:window(),
          outstream_offset :: non_neg_integer(),
          callback_module :: term(),
          callback_state :: term()
         }).
-type state() :: #state{}.
-export_type([state/0]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type data_packing() :: raw | data_kv.
-export_type([data_packing/0]).

-type reaction() :: ({change_state, NewState :: term()} |
                     {send, Value :: outbound_value()} |
                     {send, Value :: outbound_value(),
                      OptionalHeaders :: [quic_connection:optional_header()]}).
-export_type([reaction/0]).

-type outbound_value() :: iodata() | data_kv() | {pre_encoded, iodata()}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec on_start(StreamId :: stream_id(), CallbackModule :: module(), CallbackStartArgs :: [term()])
        -> {Reactions :: [quic_connection:stream_reaction()], State :: state()}.
on_start(StreamId, CallbackModule, CallbackStartArgs) ->
    {DataPacking, CallbackState, Reactions} = CallbackModule:on_start_cb(CallbackStartArgs),
    InitialState =
        #state{
           stream_id = StreamId,
           data_packing = DataPacking,
           instream = new_instream(DataPacking),
           outstream_offset = 0,
           callback_module = CallbackModule,
           callback_state = CallbackState
          },
    {ConnStreamReactions, _} =
        quic_util:filtermapfoldl(
          fun handle_reaction/2, InitialState, Reactions),
    {ConnStreamReactions, InitialState}.

-spec on_inbound_data(Offset :: non_neg_integer(), Data :: iodata(), State :: state())
        -> {Reactions :: [quic_connection:stream_reaction()], NewState :: state()}.
on_inbound_data(Offset, Data, State) ->
    StateB = insert_into_instream(Offset, Data, State),
    {ConsumedValue, StateC} = consume_instream_value(StateB),
    case is_consumed_value_empty(ConsumedValue, StateC#state.data_packing) of
        true -> {[], StateC};
        false -> handle_consumed_value(ConsumedValue, StateC)
    end.

-spec on_outbound_data(Data :: iodata(), State :: state())
        -> {Offset :: non_neg_integer(), NewState :: state()}.
on_outbound_data(Data, State) ->
    DataSize = iolist_size(Data),
    Offset = State#state.outstream_offset,
    NewOffset = Offset + DataSize,
    NewState = State#state{ outstream_offset = NewOffset },
    {Offset, NewState}.

-spec callback_state(State :: state()) -> CallbackState :: term().
callback_state(#state{ callback_state = CallbackState }) ->
    CallbackState.

-spec set_callback_state(State :: state(), CallbackState :: term()) -> state().
set_callback_state(State, CallbackState) ->
    State#state{ callback_state = CallbackState }.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

new_instream(raw) ->
    quic_instream_unordered_data:new();
new_instream(data_kv) ->
    DataInstream = quic_instream_unordered_data:new(),
    quic_instream_data_kv:new(DataInstream).

insert_into_instream(Offset, Data, State) ->
    Instream = State#state.instream,
    {ok, NewInstream} = quic_instream:insert(Instream, Offset, Data),
    State#state{ instream = NewInstream }.

consume_instream_value(State) ->
    Instream = State#state.instream,
    {NewInstream, ConsumedValue} = quic_instream:consume(Instream),
    {ConsumedValue, State#state{ instream = NewInstream }}.

-spec is_consumed_value_empty(iodata() | data_kv(), data_packing())
        -> boolean().
is_consumed_value_empty(Data, raw) ->
    iolist_size(Data) < 1;
is_consumed_value_empty(DataKvs, data_kv) ->
    DataKvs =:= [].

handle_consumed_value(Consumed, State) ->
    #state{ callback_module = CallbackModule,
            callback_state = CallbackState } = State,
    {Reactions, NewCallbackState} = CallbackModule:on_inbound_cb(Consumed, CallbackState),
    NewState = State#state{ callback_state = NewCallbackState },
    {ConnStreamReactions, _} =
        quic_util:filtermapfoldl(
          fun handle_reaction/2, NewState, Reactions),
    {ConnStreamReactions, NewState}.

pack_outbound_value(Data, raw) when is_list(Data); is_binary(Data) ->
    Data;
pack_outbound_value(#data_kv{} = DataKv, data_kv) ->
    quic_data_kv:encode(DataKv);
pack_outbound_value({pre_encoded, Data}, data_kv) when is_list(Data); is_binary(Data) ->
    Data.

handle_reaction({change_state, NewCallbackState}, State) ->
    NewState = State#state{ callback_state = NewCallbackState },
    {{true, {change_state, NewState}}, NewState};
handle_reaction({send, Value}, State) ->
    Data = pack_outbound_value(Value, State#state.data_packing),
    {{true, {send, Data}}, State};
handle_reaction({send, Value, OptionalHeaders}, State) ->
    Data = pack_outbound_value(Value, State#state.data_packing),
    {{true, {send, Data, OptionalHeaders}}, State}.
