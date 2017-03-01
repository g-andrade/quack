-module(quic_stream_handler).
-include("quic_frame.hrl").

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type data_packing() :: raw | data_kv | http.
-export_type([data_packing/0]).

%% ------------------------------------------------------------------
%% Callbacks
%% ------------------------------------------------------------------

-callback start_instream(HandlerPid :: pid(), StreamId :: stream_id(), InstreamPid :: pid()) -> {ok, DataPacking :: data_packing()}.
-callback start_outstream(HandlerPid :: pid(), StreamId :: stream_id(), OutstreamPid :: pid()) -> {ok, DataPacking :: data_packing()}.
-callback handle_inbound(HandlerPid :: pid(), StreamId :: stream_id(), Value :: term()) -> ok.
