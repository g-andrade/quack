-module(quic_rst_stream_error).
-export([decode/1]).
-export([encode/1]).

%
% Taken from Chromium: "net/quic/core/quic_error_codes.h" @ 05124be
%

-type decoded_value() :: (
        % Complete response has been sent, sending a RST to ask the other endpoint
        % to stop sending request data without discarding the response.
        stream_no_error

        % There was some error which halted stream processing.
        | error_processing_stream

        % We got two fin or reset offsets which did not match.
        | multiple_termination_offsets

        % We got bad payload and can not respond to it at the protocol level.
        | bad_application_payload

        % Stream closed due to connection error. No reset frame is sent when this
        % happens.
        | stream_connection_error

        % GoAway frame sent. No more stream can be created.
        | stream_peer_going_away

        % The stream has been cancelled.
        | stream_cancelled

        % Closing stream locally, sending a RST to allow for proper flow control
        % accounting. Sent in response to a RST from the peer.
        | rst_acknowledgment

        % Receiver refused to create the stream (because its limit on open streams
        % has been reached).  The sender should retry the request later (using
        % another stream).
        | refused_stream

        % Invalid URL in PUSH_PROMISE request header.
        | invalid_promise_url

        % Server is not authoritative for this URL.
        | unauthorized_promise_url

        % Can't have more than one active PUSH_PROMISE per URL.
        | duplicate_promise_url

        % Vary check failed.
        | promise_vary_mismatch

        % Only GET and HEAD methods allowed.
        | invalid_promise_method

        % The push stream is unclaimed and timed out.
        | push_stream_timed_out

        % Received headers were too large.
        | headers_too_large

        | {unknown, non_neg_integer()}).

-export_type([decoded_value/0]).

-type encoded_value() :: 0..15.
-export_type([encoded_value/0]).

decode(0) -> stream_no_error;
decode(1) -> error_processing_stream;
decode(2) -> multiple_termination_offsets;
decode(3) -> bad_application_payload;
decode(4) -> stream_connection_error;
decode(5) -> stream_peer_going_away;
decode(6) -> stream_cancelled;
decode(7) -> rst_acknowledgment;
decode(8) -> refused_stream;
decode(9) -> invalid_promise_url;
decode(10) -> unauthorized_promise_url;
decode(11) -> duplicate_promise_url;
decode(12) -> promise_vary_mismatch;
decode(13) -> invalid_promise_method;
decode(14) -> push_stream_timed_out;
decode(15) -> headers_too_large;
decode(Unknown) -> {unknown, Unknown}.

encode(stream_no_error) -> 0;
encode(error_processing_stream) -> 1;
encode(multiple_termination_offsets) -> 2;
encode(bad_application_payload) -> 3;
encode(stream_connection_error) -> 4;
encode(stream_peer_going_away) -> 5;
encode(stream_cancelled) -> 6;
encode(rst_acknowledgment) -> 7;
encode(refused_stream) ->  8;
encode(invalid_promise_url) -> 9;
encode(unauthorized_promise_url) -> 10;
encode(duplicate_promise_url) -> 11;
encode(promise_vary_mismatch) -> 12;
encode(invalid_promise_method) -> 13;
encode(push_stream_timed_out) -> 14;
encode(headers_too_large) -> 15.
