-module(quack).
-export([connect/4]).
-export([close/1]).

connect(RemoteEndpoint, RemotePort, DefaultStreamHandler, DefaultStreamHandlerPid) ->
    ConnectionArgs = [self(), RemoteEndpoint, RemotePort, DefaultStreamHandler, DefaultStreamHandlerPid],
    {ok, _Connection} = quic_connection_sup:start_connection(ConnectionArgs).

close(Connection) ->
    quic_connection:close(Connection).
