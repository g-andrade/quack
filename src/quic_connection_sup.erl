-module(quic_connection_sup).
-behaviour(supervisor).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).
-export([start_connection/1]).

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
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_connection(ConnectionArgs) ->
    {ok, ComponentSupervisorPid} = supervisor:start_child(?MODULE, [ConnectionArgs]),
    ConnectionPid = quic_connection_components_sup:get_connection_pid(ComponentSupervisorPid),
    {ok, ConnectionPid}.

%% ------------------------------------------------------------------
%% supervisor Function Definitions
%% ------------------------------------------------------------------

init([]) ->
    {ok, {{simple_one_for_one, 100, 1},
          [?CHILD(quic_connection_components_sup, supervisor)]
         }}.
