-module(quic_stream_handler).
-include("quic_frame.hrl").

-callback start_stream(HandlerPid :: pid(), StreamId :: stream_id(), StreamPid :: pid()) -> {ok, DataPacking :: quic_stream:data_packing()}.

-callback handle_inbound(HandlerPid :: pid(), StreamId :: stream_id(), Value :: term()) -> ok.
