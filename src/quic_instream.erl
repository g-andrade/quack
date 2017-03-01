-module(quic_instream).
-behaviour(gen_server).

-include("quic_data_kv.hrl").
-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/3]). -ignore_xref({start_link, 3}).
-export([dispatch_frame/2]).

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
          data_packing :: quic_stream_handler:data_packing(),
          handler_module :: module(),
          handler_pid :: pid(),
          instream_window :: quic_instream_window:window()
         }).
-type state() :: #state{}.
-export_type([state/0]).

-type dispatch_option() :: quic_outflow:packet_option().
-export_type([dispatch_option/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(StreamId, HandlerModule, HandlerPid) ->
    gen_server:start_link(?CB_MODULE,
                          [StreamId, HandlerModule, HandlerPid],
                          []).

-spec dispatch_frame(Pid :: pid(), Frame :: stream_frame() | stream_fin_frame()) -> ok.
dispatch_frame(Pid, Frame) ->
    gen_server:cast(Pid, {inbound_frame, Frame}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([StreamId, HandlerModule, HandlerPid]) ->
    gen_server:cast(self(), {initialize, StreamId, HandlerModule, HandlerPid}),
    {ok, uninitialized}.

handle_call(Request, From, State) when State =/= uninitialized ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast({initialize, StreamId, HandlerModule, HandlerPid}, uninitialized) ->
    {ok, DataPacking} = HandlerModule:start_instream(HandlerPid, StreamId, self()),
    InitialState =
        #state{
           stream_id = StreamId,
           data_packing = DataPacking,
           handler_module = HandlerModule,
           handler_pid = HandlerPid,
           instream_window = new_instream_window(DataPacking)
          },
    {noreply, InitialState};
handle_cast({inbound_frame, #stream_frame{} = Frame}, State) ->
    #stream_frame{ offset = Offset,
                   data_payload = Data } = Frame,
    StateB = insert_into_instream_window(Offset, Data, State),
    {StateC, ConsumedValue} = consume_instream_window_value(StateB),
    (is_consumed_value_empty(ConsumedValue, StateC#state.data_packing)
     orelse handle_consumed_value(ConsumedValue, StateC)),
    {noreply, StateC};
handle_cast(Msg, State) when State =/= uninitialized ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

handle_info(Info, State) when State =/= uninitialized ->
    lager:debug("unhandled info ~p on state ~p", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

new_instream_window(raw) ->
    quic_instream_window_unordered_data:new();
new_instream_window(data_kv) ->
    DataInstream = quic_instream_window_unordered_data:new(),
    quic_instream_window_data_kv:new(DataInstream);
new_instream_window(http) ->
    DataInstream = quic_instream_window_unordered_data:new(),
    quic_instream_window_http:new(DataInstream).

insert_into_instream_window(Offset, Data, State) ->
    Instream = State#state.instream_window,
    case quic_instream_window:insert(Instream, Offset, Data) of
        {ok, NewInstream} ->
            State#state{ instream_window = NewInstream };
        {error, stale_data} ->
            lager:debug("got outdated data for stream ~p, offset ~p, with length ~p",
                        [State#state.stream_id, Offset, iolist_size(Data)]),
            State
    end.

consume_instream_window_value(State) ->
    Instream = State#state.instream_window,
    {NewInstream, ConsumedValue} = quic_instream_window:consume(Instream),
    NewState = State#state{ instream_window = NewInstream },
    {NewState, ConsumedValue}.

-spec is_consumed_value_empty(iodata() | [data_kv()] | [h2_frame:frame()], quic_stream_handler:data_packing())
        -> boolean().
is_consumed_value_empty(Data, raw) ->
    iolist_size(Data) < 1;
is_consumed_value_empty(DataKvs, data_kv) ->
    DataKvs =:= [];
is_consumed_value_empty(HttpFrames, http) ->
    HttpFrames =:= [].

handle_consumed_value(Consumed, State) ->
    #state{ stream_id = StreamId,
            handler_module = HandlerModule,
            handler_pid = HandlerPid } = State,
    ok = HandlerModule:handle_inbound(HandlerPid, StreamId, Consumed).
