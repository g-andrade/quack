-module(quic_outstream).
-behaviour(gen_server).

-include("quic_data_kv.hrl").
-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/4]). -ignore_xref({start_link, 4}).
-export([dispatch_value/2]).
-export([dispatch_value/3]).

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
          outflow_pid :: pid(),
          outflow_monitor :: reference(),
          handler_module :: module(),
          handler_pid :: pid(),
          outstream_offset :: non_neg_integer()
         }).
-type state() :: #state{}.
-export_type([state/0]).

-type dispatch_option() :: quic_outflow:packet_option().
-export_type([dispatch_option/0]).

-type http_frame() :: h2_frame:frame().

-type outbound_value() :: iodata() | data_kv() | {raw, iodata()} | [http_frame()].


%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(OutflowPid, StreamId, HandlerModule, HandlerPid) ->
    gen_server:start_link(?CB_MODULE,
                          [OutflowPid, StreamId,
                           HandlerModule, HandlerPid],
                          []).

-spec dispatch_value(Pid :: pid(), OutboundValue :: outbound_value()) -> ok.
dispatch_value(Pid, OutboundValue) ->
    dispatch_value(Pid, OutboundValue, []).

-spec dispatch_value(
        Pid :: pid(), OutboundValue :: outbound_value(),
        Options :: [dispatch_option()]) -> ok.
dispatch_value(Pid, OutboundValue, Options) ->
    gen_server:cast(Pid, {outbound_value, OutboundValue, Options}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init(Args) ->
    gen_server:cast(self(), {initialize, Args}),
    {ok, uninitialized}.

handle_call(Request, From, State) when State =/= uninitialized ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast({initialize, [OutflowPid, StreamId, HandlerModule, HandlerPid]}, uninitialized) ->
    {ok, DataPacking} = HandlerModule:start_outstream(HandlerPid, StreamId, self()),
    InitialState =
        #state{
           stream_id = StreamId,
           data_packing = DataPacking,
           outflow_pid = OutflowPid,
           outflow_monitor = monitor(process, OutflowPid),
           handler_module = HandlerModule,
           handler_pid = HandlerPid,
           outstream_offset = 0
          },
    {noreply, InitialState};
handle_cast({outbound_value, OutboundValue, Options}, State) ->
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
    quic_outflow:dispatch_frame(State#state.outflow_pid, Frame, Options),
    {noreply, NewState};
handle_cast(Msg, State) when State =/= uninitialized ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

handle_info({'DOWN', Reference, process, _Pid, _Reason}, State)
  when Reference =:= State#state.outflow_monitor ->
    {stop, normal, State};
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

pack_outbound_value(Data, raw) when is_list(Data); is_binary(Data) ->
    Data;
pack_outbound_value(#data_kv{} = DataKv, data_kv) ->
    quic_data_kv:encode(DataKv);
pack_outbound_value({raw, Data}, data_kv) when is_list(Data); is_binary(Data) ->
    Data;
pack_outbound_value(HttpFrame, http) ->
    h2_frame:to_binary(HttpFrame).
