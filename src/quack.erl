-module(quack).
-export([connect/4]).
-export([close/1]).
-export([open_outstream/2]).

connect(RemoteEndpoint, RemotePort, DefaultStreamHandler, DefaultStreamHandlerPid) ->
    ConnectionArgs = [self(), RemoteEndpoint, RemotePort, DefaultStreamHandler, DefaultStreamHandlerPid],
    {ok, _Connection} = quic_connection_sup:start_connection(ConnectionArgs).

close(#{ connection_pid := ConnectionPid }) ->
    quic_connection:close(ConnectionPid).

open_outstream(#{ outflow_pid := OutflowPid,
                  outstreams_supervisor_pid := OutstreamsSupervisorPid,
                  default_stream_handler := DefaultStreamHandler,
                  default_stream_handler_pid := DefaultStreamHandlerPid },
               StreamId) ->
    % TODO avoid possibility of creating outstreams with repeated IDs (some kind of outstream manager?)
    {ok, _OutstreamPid} =
        quic_outstreams_sup:start_outstream(
          OutstreamsSupervisorPid, OutflowPid,
          StreamId, DefaultStreamHandler, DefaultStreamHandlerPid),
    ok.
