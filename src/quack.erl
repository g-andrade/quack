-module(quack).
-export([connect/2]).
-export([close/1]).

connect(RemoteEndpoint, RemotePort) ->
    ConnectionArgs = [self(), RemoteEndpoint, RemotePort],
    {ok, _Connection} = quic_connection_sup:start_connection(ConnectionArgs).

close(Connection) ->
    quic_connection:close(Connection).
