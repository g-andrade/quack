-module(quic_connection_components_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/1]).
-export([get_connection_pid/1]).
-export([start_remaining_components/5]).

%% ------------------------------------------------------------------
%% supervisor Function Exports
%% ------------------------------------------------------------------

-export([init/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, temporary, 5000, Type, [I]}).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(ConnectionArgs) ->
    supervisor:start_link(?MODULE, [ConnectionArgs]).

get_connection_pid(SupervisorPid) ->
    AllChildren = supervisor:which_children(SupervisorPid),
    {_Id, Pid, _Type, _Modules} = lists:keyfind(quic_connection, 1, AllChildren),
    Pid.

start_remaining_components(SupervisorPid, ConnectionModule,
                           ConnectionPid, ConnectionId, CryptoStreamId) ->
    OutflowChild = ?CHILD(quic_outflow, worker, [ConnectionPid, ConnectionId]),
    {ok, OutflowPid} = supervisor:start_child(SupervisorPid, OutflowChild),

    CryptoModule = quic_crypto,
    CryptoChild = ?CHILD(CryptoModule, worker, [ConnectionId]),
    {ok, CryptoPid} = supervisor:start_child(SupervisorPid, CryptoChild),
    {ok, CryptoShadowState} =
        CryptoModule:subscribe_shadow_state(CryptoPid, ConnectionModule,
                                           ConnectionPid),

    CryptoStreamChild = ?CHILD(quic_stream, worker, [CryptoStreamId, OutflowPid,
                                                     CryptoModule, CryptoPid]),
    {ok, CryptoStreamPid} = supervisor:start_child(SupervisorPid, CryptoStreamChild),

    InflowInitialStreams = #{CryptoStreamId => CryptoStreamPid},
    InflowChild = ?CHILD(quic_inflow, worker, [OutflowPid, InflowInitialStreams]),
    {ok, InflowPid} = supervisor:start_child(SupervisorPid, InflowChild),

    {ok, {InflowPid, OutflowPid, CryptoPid, CryptoShadowState}}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

init([ConnectionArgs]) ->
    ConnectionChild = ?CHILD(quic_connection, worker, [self() | ConnectionArgs]),
    {ok, {{one_for_all, 10, 1}, [ConnectionChild]}}.
