-module(quic_stream_handler).

-callback start_stream(HandlerPid :: pid(), StreamPid :: pid()) -> {ok, DataPacking :: quic_stream:data_packing()}.

-callback handle_inbound(HandlerPid :: pid(), Value :: term()) -> ok.
