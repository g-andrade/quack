-module(quic_outflow).
-behaviour(gen_server).

-include("quic_frame.hrl").
-include("quic_packet.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/2]). -ignore_xref({start_link, 2}).
-export([dispatch_frame/2]).
-export([dispatch_frame/3]).
-export([dispatch_packet/2]).
-export([dispatch_inbound_ack/2]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(CB_MODULE, ?MODULE).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(state, {
          connection_pid :: pid(),
          connection_monitor :: reference(),
          connection_id :: connection_id(),
          prev_packet_number :: packet_number(),
          % @TODO: use a more performant data structure for this?
          unacked_packets :: [unacked_packet()]
         }).
-type state() :: #state{}.
-export_type([state/0]).

-record(unacked_packet, {
          packet_number :: packet_number(),
          timestamp :: non_neg_integer(), % in microseconds
          packet :: outbound_regular_packet()
         }).
-type unacked_packet() :: #unacked_packet{}.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type optional_packet_header() :: ({version, iodata()} |               % 4 bytes
                                   {diversification_nonce, iodata()}). % 32 bytes
-export_type([optional_packet_header/0]).

-type packet_option() :: ({headers, [optional_packet_header(), ...]} |
                                   {crypto_state, quic_crypto:state()}).
-export_type([packet_option/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(ConnectionPid, ConnectionId) ->
    gen_server:start_link(?CB_MODULE, [ConnectionPid, ConnectionId], []).

-spec dispatch_frame(OutflowPid :: pid(), Frame :: frame()) -> ok.
dispatch_frame(OutflowPid, Frame) ->
    dispatch_frame(OutflowPid, Frame, []).

-spec dispatch_frame(OutflowPid :: pid(), Frame :: frame(),
                     PacketOptions :: [packet_option()])
        -> ok.
dispatch_frame(OutflowPid, Frame, PacketOptions) ->
    gen_server:cast(OutflowPid, {frame, Frame, PacketOptions}).

-spec dispatch_packet(OutflowPid :: pid(), Packet :: quic_packet()) -> ok.
dispatch_packet(OutflowPid, Packet) ->
    gen_server:cast(OutflowPid, {packet, Packet}).

-spec dispatch_inbound_ack(OutflowPid :: pid(), AckFrame :: ack_frame()) -> ok.
dispatch_inbound_ack(OutflowPid, AckFrame) ->
    gen_server:cast(OutflowPid, {inbound_ack, AckFrame}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([ConnectionPid, ConnectionId]) ->
    InitialState =
        #state{
           connection_pid = ConnectionPid,
           connection_monitor = monitor(process, ConnectionPid),
           connection_id = ConnectionId,
           prev_packet_number = 0,
           unacked_packets = [] },
    {ok, InitialState}.

handle_call(Request, From, State) ->
    lager:debug("unhandled call ~p from ~p on state ~p",
                [Request, From, State]),
    {noreply, State}.

handle_cast({frame, Frame, PacketOptions}, State) ->
    OptionalPacketHeaders = proplists:get_value(headers, PacketOptions, []),
    #state{ connection_id = ConnectionId } = State,
    Packet =
        #outbound_regular_packet{
           connection_id = ConnectionId,
           version = proplists:get_value(version, OptionalPacketHeaders),
           diversification_nonce = proplists:get_value(diversification_nonce, OptionalPacketHeaders),
           frames = [Frame],
           crypto_state = proplists:get_value(crypto_state, PacketOptions, current) },
    on_outbound_packet(Packet, State);
handle_cast({packet, Packet}, State) ->
    on_outbound_packet(Packet, State);
handle_cast({inbound_ack, AckFrame}, State) ->
    {noreply, handle_inbound_ack(AckFrame, State)};
handle_cast(Msg, State) ->
    lager:debug("unhandled cast ~p on state ~p", [Msg, State]),
    {noreply, State}.

handle_info({'DOWN', Reference, process, _Pid, _Reason}, State)
  when Reference =:= State#state.connection_monitor ->
    {stop, normal, State};
handle_info(Info, State) ->
    lager:debug("unhandled info ~p on state ~p", [Info, State]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec handle_inbound_ack(AckFrame :: ack_frame(), state()) -> state().
handle_inbound_ack(AckFrame, State) ->
    % @TODO: look at largest_received_time_delta to ease of resending
    #ack_frame{
       largest_received = LargestReceivedPacketNumber,
       received_packet_blocks = ReceivedPacketBlocks } = AckFrame,

    lager:debug("got ack: largest received ~p, packet blocks ~p",
                [LargestReceivedPacketNumber, ReceivedPacketBlocks]),
    UnackedPackets = State#state.unacked_packets,
    debug_unacked_packet_numbers("old unacked packets: ", UnackedPackets),
    NewUnackedPackets =
        filter_unacked_packets(UnackedPackets, LargestReceivedPacketNumber,
                               ReceivedPacketBlocks),
    debug_unacked_packet_numbers("new unacked packets: ", NewUnackedPackets),
    NewState = State#state{ unacked_packets = NewUnackedPackets },
    resend_all_below_largest_received(LargestReceivedPacketNumber, NewState).

-spec on_outbound_packet(NumberlessPacket :: outbound_regular_packet(), State :: state())
        -> {noreply, state()} | {stop, normal, state()}.
on_outbound_packet(NumberlessPacket, State) ->
    #state{ prev_packet_number = PrevPacketNumber,
            unacked_packets = UnackedPackets } = State,
    PacketNumber = PrevPacketNumber + 1,
    Packet = NumberlessPacket#outbound_regular_packet{ packet_number = PacketNumber },
    UnackedPacket =
        #unacked_packet{
           packet_number = PacketNumber,
           timestamp = quic_util:now_us(),
           packet = Packet },
    NewUnackedPackets = [UnackedPacket | UnackedPackets],
    NewState =
        State#state{
          prev_packet_number = PacketNumber,
          unacked_packets = NewUnackedPackets },

    ConnectionPid = State#state.connection_pid,
    quic_connection:dispatch_packet(ConnectionPid, Packet),
    case should_stop_after_sending_packet(Packet) of
        false -> {noreply, NewState};
        true -> {stop, normal, NewState}
    end.

filter_unacked_packets(UnackedPackets, LargestReceivedPacketNumber, ReceivedPacketBlocks) ->
    {RecentUnacked, RemainingPackets} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber > LargestReceivedPacketNumber
          end,
          UnackedPackets),

    RecentUnacked ++
        filter_old_unacked_packets(RemainingPackets, LargestReceivedPacketNumber,
                                   ReceivedPacketBlocks).

filter_old_unacked_packets([] = UnackedPackets, _ReceivedPacketNumber,
                           _Blocks) ->
    UnackedPackets;
filter_old_unacked_packets(UnackedPackets, _ReceivedPacketNumber,
                           [] = _Blocks) ->
    UnackedPackets;
filter_old_unacked_packets(UnackedPackets, ReceivedPacketNumber,
                           [FirstBlock | RemainingBlocks]) ->
    #ack_received_packet_block{ gap_from_prev_block = GapFromPrevBlock,
                                ack_block_length = BlockLength } = FirstBlock,

    UnreceivedFloor = ReceivedPacketNumber - GapFromPrevBlock,
    {Unacked, RemainingPackets} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber > UnreceivedFloor
          end,
          UnackedPackets),

    ReceivedFloor = UnreceivedFloor - BlockLength,
    {_Acked, NextUnacked} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber >= ReceivedFloor
          end,
          RemainingPackets),

    Unacked ++ filter_unacked_packets(NextUnacked, ReceivedFloor, RemainingBlocks).

debug_unacked_packet_numbers(Msg, UnackedPackets) ->
    lager:debug("~s~p",
                [Msg,
                 list_to_tuple([UnackedPacket#unacked_packet.packet_number
                                || UnackedPacket <- UnackedPackets])]).

%
% @TODO actually rate limit this? (as well as sending in general)
%
resend_all_below_largest_received(LargestReceivedPacketNumber, State) ->
    UnackedPackets = State#state.unacked_packets,
    {NewUnackedPackets, UnackedPacketsToResend} =
        lists:splitwith(
          fun (#unacked_packet{ packet_number = PacketNumber }) ->
                  PacketNumber >= LargestReceivedPacketNumber
          end,
          UnackedPackets),
    NewState = State#state{ unacked_packets = NewUnackedPackets },

    (UnackedPacketsToResend =/= []
     andalso
     begin
         [#unacked_packet{ packet_number = HighestResendingPacketNumber } | _] =
            UnackedPacketsToResend,
         debug_unacked_packet_numbers("resending packets ", UnackedPacketsToResend),
         StopWaitingPacketNumber = HighestResendingPacketNumber + 1,
         PacketsToResend =
            lists:foldl(
              fun (#unacked_packet{ packet = Packet }, Acc) ->
                      [Packet | Acc]
              end,
              [],
              UnackedPacketsToResend),

         StopWaitingFrame =
            #stop_waiting_frame{
               least_unacked_packet_number = StopWaitingPacketNumber },
         dispatch_frame(self(), StopWaitingFrame),

         lists:foreach(
           fun (Packet) ->
                   dispatch_packet(self(), Packet)
           end,
           PacketsToResend)
     end),
    NewState.

should_stop_after_sending_packet(#version_negotiation_packet{}) ->
    false;
should_stop_after_sending_packet(#public_reset_packet{}) ->
    true;
should_stop_after_sending_packet(#outbound_regular_packet{ frames = Frames }) ->
    lists:any(
      fun (#connection_close_frame{}) ->
              true;
          (_) ->
              false
      end,
      Frames).
