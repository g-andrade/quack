-module(test_quic_http_request).
-behaviour(gen_server).
-behaviour(quic_stream_handler).

-include_lib("chatterbox/include/http2.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([do_it/0]).
-export([do_it/2]).

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
%% quic_stream_handler Function Exports
%% ------------------------------------------------------------------

-export([start_instream/3]).
-export([start_outstream/3]).
-export([handle_inbound/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

-define(HTTP2_HEADERS_STREAM_ID, 3).
-define(HEADER_TABLE_SIZE, 4096). % hpack

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          remote_endpoint,
          remote_port,
          connection,
          outstreams,
          headers_encode_context
         }).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

do_it() ->
    do_it("www.google.com", 443).

do_it(RemoteEndpoint, RemotePort) ->
    gen_server:start_link(?CB_MODULE, [RemoteEndpoint, RemotePort], []).

%% ------------------------------------------------------------------
%% quic_stream_handler Function Definitions
%% ------------------------------------------------------------------

start_instream(Pid, StreamId, _InstreamPid) ->
    gen_server:call(Pid, {start_instream, StreamId}).

start_outstream(Pid, StreamId, OutstreamPid) ->
    gen_server:call(Pid, {start_outstream, StreamId, OutstreamPid}).

handle_inbound(Pid, StreamId, Value) ->
    gen_server:cast(Pid, {stream_inbound, StreamId, Value}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([RemoteEndpoint, RemotePort]) ->
    gen_server:cast(self(), start),
    {ok, #state{ remote_endpoint = RemoteEndpoint,
                 remote_port = RemotePort,
                 outstreams = #{} }}.

handle_call({start_instream, StreamId}, _From, State) ->
    lager:debug("starting instream ~p", [StreamId]),
    {reply, {ok, http}, State};
handle_call({start_outstream, StreamId, OutstreamPid}, _From, State) ->
    lager:debug("starting outstream ~p", [StreamId]),
    Outstreams = State#state.outstreams,
    NewOutstreams = maps:put(StreamId, OutstreamPid, Outstreams),
    NewState = State#state{ outstreams = NewOutstreams },
    on_outstream_started(StreamId, NewState);
handle_call(Request, From, State) ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast(start, State) ->
    #state{ remote_endpoint = RemoteEndpoint,
            remote_port = RemotePort } = State,
    {ok, Connection} = quack:connect(RemoteEndpoint, RemotePort, ?MODULE, self()),
    ok = quack:open_outstream(Connection, ?HTTP2_HEADERS_STREAM_ID),
    {noreply, State#state{ connection = Connection }};
handle_cast({stream_inbound, StreamId, Value}, State) ->
    lager:debug("got data from stream ~p: ~p", [StreamId, Value]),
    handle_inbound_data(StreamId, Value, State);
handle_cast(Msg, State) ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

handle_info(Info, State) ->
    lager:debug("unhandled info ~p on state ~p", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) ->
    %ok = quack:close(Connection),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

%
% An ongoing, very confusing mix of:
%   https://quicwg.github.io/base-drafts/draft-ietf-quic-http.html#rfc.section.5
%   https://tools.ietf.org/html/draft-tsvwg-quic-protocol-00
%
% ..and other sources
%

on_outstream_started(StreamId, State) when StreamId =:= ?HTTP2_HEADERS_STREAM_ID ->
    InitialEncodeContext = hpack:new_context(?HEADER_TABLE_SIZE),
    RequestHeaders =
        [{<<":method">>, <<"GET">>},
         {<<":path">>, <<"/">>},
         {<<":scheme">>, <<"https">>}
         ],
    {ok, {EncodedRequestHeaders, EncodeContext}} =
        hpack:encode(RequestHeaders, InitialEncodeContext),

    PriorityFramePayload = h2_frame_priority:new(0, ?HTTP2_HEADERS_STREAM_ID, 1),
    HeadersFramePayload = h2_frame_headers:new(PriorityFramePayload, EncodedRequestHeaders),
    HeadersFrameHeader =
        #frame_header{
           flags = (16#04 bor % "This frame concludes a header block."
                    16#20),   % Priority info is present
           stream_id = StreamId
          },
    HeadersFrame = {HeadersFrameHeader, HeadersFramePayload},

    send_to_outstream(StreamId, HeadersFrame, State),
    NewState = State#state{ headers_encode_context = EncodeContext },
    {reply, {ok, http}, NewState};
on_outstream_started(_StreamId, State) ->
    {reply, {ok, http}, State}.

send_to_outstream(StreamId, Value, State) ->
    OutstreamPid = maps:get(StreamId, State#state.outstreams),
    quic_outstream:dispatch_value(OutstreamPid, Value).

handle_inbound_data(StreamId, HttpFrames, State) when StreamId =:= ?HTTP2_HEADERS_STREAM_ID ->
    handle_inbound_http_frames(StreamId, HttpFrames, State);
handle_inbound_data(_StreamId, _Value, State) ->
    {noreply, State}.

handle_inbound_http_frames(_StreamId, [], State) ->
    {noreply, State};
handle_inbound_http_frames(StreamId, [{Header, _Payload} = Frame | NextFrames], State)
  when Header#frame_header.type =:= ?HEADERS ->
    EncodedResponseHeaders = h2_frame_headers:from_frames([Frame]),
    EncodeContext = State#state.headers_encode_context,
    {ok, {ResponseHeaders, NewEncodeContext}} =
        hpack:decode(EncodedResponseHeaders, EncodeContext),
    lager:debug("decoded response headers: ~p", [ResponseHeaders]),
    NewState = State#state{ headers_encode_context = NewEncodeContext },
    handle_inbound_http_frames(StreamId, NextFrames, NewState).
