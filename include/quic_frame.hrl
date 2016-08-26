-ifndef(QUIC_FRAME_HRL).
-define(QUIC_FRAME_HRL, included).

-include("quic_numeric.hrl").
-include("quic_packet.hrl").

-type frame() :: (stream_frame() | ack_frame() | padding_frame() | reset_stream_frame() |
                  connection_close_frame() | go_away_frame() | window_update_frame() |
                  blocked_frame() | stop_waiting_frame() | ping_frame()).

%% ------------------------------------------------------------------
%% Stream frame
%% ------------------------------------------------------------------

-record(stream_frame, {
          % "To avoid stream ID collision, the Stream-ID must be even if the server initiates
          %  the stream, and odd if the client initiates the stream. 0 is not a valid Stream-ID.
          %  Stream 1 is reserved for the crypto handshake, which should be the first client-initiated
          %  stream. When using HTTP/2 over QUIC, Stream 3 is reserved for transmitting compressed
          %  headers for all other streams, ensuring reliable in-order delivery and processing of
          %  headers."
          %
          stream_id :: stream_id(),
          offset :: stream_offset(),
          data_payload :: binary()
         }).
-type stream_frame() :: #stream_frame{}.

-record(stream_fin_frame, {
          stream_id :: stream_id()
         }).
-type stream_fin_frame() :: #stream_fin_frame{}.

-type stream_id() :: uint32().
-type stream_offset() :: uint64().

%% ------------------------------------------------------------------
%% Ack frame
%% ------------------------------------------------------------------

-record(ack_frame, {
          largest_acked :: packet_number(),
          largest_acked_delta_time :: binary(), % @TODO: support custom 16-bit floating point format
          packet_timestamps :: [ack_frame_packet_timestamp()]
         }).
-type ack_frame() :: #ack_frame{}.

-record(ack_frame_packet_timestamp, {
          packet_number :: packet_number(),
          timestamp :: binary() % in microseconds
         }).
-type ack_frame_packet_timestamp() :: #ack_frame_packet_timestamp{}.

%% ------------------------------------------------------------------
%% Padding frame
%% ------------------------------------------------------------------

-record(padding_frame, {
          size :: non_neg_integer()
         }).
-type padding_frame() :: #padding_frame{}.

%% ------------------------------------------------------------------
%% Reset stream frame
%% ------------------------------------------------------------------

-record(reset_stream_frame, {
          stream_id :: stream_id(),
          byte_offset :: uint64(),
          error_code :: binary()
         }).
-type reset_stream_frame() :: #reset_stream_frame{}.

%% ------------------------------------------------------------------
%% Connection close frame
%% ------------------------------------------------------------------

-record(connection_close_frame, {
          error_code :: binary(),
          reason_phrase :: binary()
         }).
-type connection_close_frame() :: #connection_close_frame{}.

%% ------------------------------------------------------------------
%% Go away frame
%% ------------------------------------------------------------------

-record(go_away_frame, {
          error_code :: binary(),
          last_good_stream_id :: stream_id(),
          reason_phrase :: binary()
         }).
-type go_away_frame() :: #go_away_frame{}.

%% ------------------------------------------------------------------
%% Window update frame
%% ------------------------------------------------------------------

-record(window_update_frame, {
          stream_id :: stream_id(),
          byte_offset :: uint64()
         }).
-type window_update_frame() :: #window_update_frame{}.

%% ------------------------------------------------------------------
%% Blocked frame
%% ------------------------------------------------------------------

-record(blocked_frame, {
          stream_id :: stream_id()
         }).
-type blocked_frame() :: #blocked_frame{}.

%% ------------------------------------------------------------------
%% Stop waiting frame
%% ------------------------------------------------------------------

-record(stop_waiting_frame, {
          least_unacked_delta :: packet_number()
         }).
-type stop_waiting_frame() :: #stop_waiting_frame{}.

%% ------------------------------------------------------------------
%% Ping frame
%% ------------------------------------------------------------------

-record(ping_frame, {}).
-type ping_frame() :: #ping_frame{}.

-endif.
