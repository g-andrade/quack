-module(quic_outstreams_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).
-export([start_outstream/5]).

%% ------------------------------------------------------------------
%% supervisor Function Exports
%% ------------------------------------------------------------------

-export([init/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CHILD(I, Type), {I, {I, start_link, []}, temporary, 5000, Type, [I]}).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
    supervisor:start_link(?MODULE, []).

start_outstream(SupervisorPid, OutflowPid, StreamId, StreamHandler, StreamHandlerPid) ->
    supervisor:start_child(SupervisorPid, [OutflowPid, StreamId, StreamHandler, StreamHandlerPid]).

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

init([]) ->
    StreamChild = ?CHILD(quic_outstream, worker),
    {ok, {{simple_one_for_one, 10, 1}, [StreamChild]}}.
