-module(quack).
-export([connect/2]).

connect(RemoteEndpoint, RemotePort) ->
    ConnectionArgs = [self(), RemoteEndpoint, RemotePort],
    {ok, ConnectionPid} = quic_connection_sup:start_connection(ConnectionArgs).
