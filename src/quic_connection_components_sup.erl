-module(quic_connection_components_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/1]).
-export([get_connection_pid/1]).
-export([start_remaining_components/8]).

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

start_remaining_components(SupervisorPid, ConnectionPid, ConnectionId,
                           CryptoStreamId, CryptoStreamHandler, CryptoStreamHandlerPid,
                           DefaultStreamHandler, DefaultStreamHandlerPid) ->
    InstreamsSupervisorChild =
        ?CHILD(quic_instreams_sup, supervisor, []),
    {ok, InstreamsSupervisorPid} = supervisor:start_child(SupervisorPid, InstreamsSupervisorChild),

    OutflowChild =
        ?CHILD(quic_outflow, worker, [ConnectionPid, ConnectionId]),
    {ok, OutflowPid} = supervisor:start_child(SupervisorPid, OutflowChild),

    OutstreamsSupervisorChild =
        ?CHILD(quic_outstreams_sup, supervisor, []),
    {ok, OutstreamsSupervisorPid} = supervisor:start_child(SupervisorPid, OutstreamsSupervisorChild),

    {ok, CryptoInstreamPid} =
       quic_instreams_sup:start_instream(InstreamsSupervisorPid,
                                         CryptoStreamId, CryptoStreamHandler, CryptoStreamHandlerPid),

    {ok, _CryptoOutstreamPid} =
       quic_outstreams_sup:start_outstream(OutstreamsSupervisorPid, OutflowPid,
                                           CryptoStreamId, CryptoStreamHandler, CryptoStreamHandlerPid),

    InflowInitialInstreams = #{CryptoStreamId => CryptoInstreamPid},
    InflowChild = ?CHILD(quic_inflow, worker, [InstreamsSupervisorPid, OutflowPid, InflowInitialInstreams,
                                               DefaultStreamHandler, DefaultStreamHandlerPid]),
    {ok, InflowPid} = supervisor:start_child(SupervisorPid, InflowChild),

    {ok, {InflowPid, OutflowPid}}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

init([ConnectionArgs]) ->
    ConnectionChild = ?CHILD(quic_connection, worker, [self() | ConnectionArgs]),
    {ok, {{one_for_all, 10, 1}, [ConnectionChild]}}.
