-module(quic_stream).
-behaviour(gen_server).

-include("quic_data_kv.hrl").
-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/4]). -ignore_xref({start_link, 4}).
-export([dispatch_inbound_frame/2]).
-export([dispatch_outbound_value/2]).
-export([dispatch_outbound_value/3]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          stream_id :: stream_id(),
          data_packing :: data_packing(),
          outflow_pid :: pid(),
          handler_module :: module(),
          handler_pid :: pid(),
          instream :: quic_instream:window(),
          outstream_offset :: non_neg_integer()
         }).
-type state() :: #state{}.
-export_type([state/0]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type data_packing() :: raw | data_kv.
-export_type([data_packing/0]).

-type outbound_value() :: iodata() | data_kv() | {raw, iodata()}.


%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(StreamId, OutflowPid, HandlerModule, HandlerPid) ->
    gen_server:start_link(?CB_MODULE,
                          [StreamId, OutflowPid,
                           HandlerModule, HandlerPid],
                          []).

-spec dispatch_inbound_frame(Pid :: pid(), Frame :: stream_frame() | stream_fin_frame()) -> ok.
dispatch_inbound_frame(Pid, Frame) ->
    gen_server:cast(Pid, {inbound_frame, Frame}).

-spec dispatch_outbound_value(Pid :: pid(), OutboundValue :: outbound_value()) -> ok.
dispatch_outbound_value(Pid, OutboundValue) ->
    dispatch_outbound_value(Pid, OutboundValue, []).

-spec dispatch_outbound_value(
        Pid :: pid(), OutboundValue :: outbound_value(),
        OptionalPacketHeaders :: [quic_outflow:optional_packet_header()]) -> ok.
dispatch_outbound_value(Pid, OutboundValue, OptionalPacketHeaders) ->
    gen_server:cast(Pid, {outbound_value, OutboundValue, OptionalPacketHeaders}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([StreamId, OutflowPid, HandlerModule, HandlerPid]) ->
    {ok, DataPacking} = HandlerModule:start_stream(HandlerPid, self()),
    InitialState =
        #state{
           stream_id = StreamId,
           data_packing = DataPacking,
           outflow_pid = OutflowPid,
           handler_module = HandlerModule,
           handler_pid = HandlerPid,
           instream = new_instream(DataPacking),
           outstream_offset = 0
          },
    {ok, InitialState}.

handle_call(Request, From, State) ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast({inbound_frame, #stream_frame{} = Frame}, State) ->
    #stream_frame{ offset = Offset,
                   data_payload = Data } = Frame,
    StateB = insert_into_instream(Offset, Data, State),
    {ConsumedValue, StateC} = consume_instream_value(StateB),
    (is_consumed_value_empty(ConsumedValue, StateC#state.data_packing)
     orelse handle_consumed_value(ConsumedValue, StateC)),
    {noreply, StateC};
handle_cast({outbound_value, OutboundValue, OptionalPacketHeaders}, State) ->
    Data = pack_outbound_value(OutboundValue, State#state.data_packing),
    DataSize = iolist_size(Data),
    Offset = State#state.outstream_offset,
    NewOffset = Offset + DataSize,
    NewState = State#state{ outstream_offset = NewOffset },
    StreamId = State#state.stream_id,
    Frame = #stream_frame{
               stream_id = StreamId,
               offset = Offset,
               data_payload = Data },
    quic_outflow:dispatch_frame(State#state.outflow_pid, Frame, OptionalPacketHeaders),
    {noreply, NewState}.

handle_info(Info, State) ->
    lager:debug("unhandled info ~p on state ~p", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

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
    case quic_instream:insert(Instream, Offset, Data) of
        {ok, NewInstream} ->
            State#state{ instream = NewInstream };
        {error, stale_data} ->
            lager:debug("got outdated data for stream ~p, offset ~p, with length ~p",
                        [State#state.stream_id, Offset, iolist_size(Data)]),
            State
    end.

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
    #state{ handler_module = HandlerModule,
            handler_pid = HandlerPid } = State,
    ok = HandlerModule:handle_inbound(HandlerPid, Consumed).

pack_outbound_value(Data, raw) when is_list(Data); is_binary(Data) ->
    Data;
pack_outbound_value(#data_kv{} = DataKv, data_kv) ->
    quic_data_kv:encode(DataKv);
pack_outbound_value({raw, Data}, data_kv) when is_list(Data); is_binary(Data) ->
    Data.
