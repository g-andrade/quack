-module(quack).
-export([connect/2]).

connect(RemoteEndpoint, RemotePort) ->
    supervisor:start_child(quic_connection_sup, [self(), RemoteEndpoint, RemotePort]).
