-ifndef(QUIC_PACKET_HRL).
-define(QUIC_PACKET_HRL, included).

-include("quic_data_kv.hrl").
-include("quic_frame.hrl").
-include("quic_numeric.hrl").

-record(public_flags, {
          version :: 0 | 1,
          reset :: 0 | 1,
          diversification_nonce :: 0 | 1,
          connection_id :: 0 | 1,
          packet_number_encoding :: 0 | 1 | 2 | 3
         }).

-record(public_reset_packet, {
          connection_id :: connection_id(),
          tagged_values :: tagged_values()
         }).
-type public_reset_packet() :: #public_reset_packet{}.

-record(version_negotiation_packet, {
          connection_id :: connection_id(),
          supported_versions :: [binary(), ...]
         }).
-type version_negotiation_packet() :: #version_negotiation_packet{}.

-record(regular_packet, {
          connection_id :: connection_id(),   % optional
          version :: binary(),                % optional
          diversification_nonce :: binary(),  % optional
          packet_number :: uint48(),          % optional
          frames :: [frame()]                 % optional
         }).
-type regular_packet() :: #regular_packet{}.

-type quic_packet() :: public_reset_packet() | version_negotiation_packet() | regular_packet().

-type connection_id() :: uint64().

-endif.
