-module(quic_error).
-export([decode/1]).
-export([encode/1]).

%
% Taken from Chromium: "net/quic/core/quic_error_codes.h" @ 05124be
%

-type decoded_value() :: (
        no_error |

        % Connection has reached an invalid state.
        internal_error |

        % There were data frames after the a fin or reset.
        stream_data_after_termination |

        % Control frame is malformed.
        invalid_packet_header |

        % Frame data is malformed.
        invalid_frame_data |

        % The packet contained no payload.
        missing_payload |

        % FEC data is malformed.
        invalid_fec_data |

        % STREAM frame data is malformed.
        invalid_stream_data |

        % STREAM frame data overlaps with buffered data.
        overlapping_stream_data |

        % Received STREAM frame data is not encrypted.
        unencrypted_stream_data |

        % Attempt to send unencrypted STREAM frame.
        attempt_to_send_unencrypted_stream_data |

        % Received a frame which is likely the result of memory corruption.
        maybe_corrupted_memory |

        % FEC frame data is not encrypted.
        unencrypted_fec_data |

        % RST_STREAM frame data is malformed.
        invalid_rst_stream_data |

        % CONNECTION_CLOSE frame data is malformed.
        invalid_connection_close_data |

        % GOAWAY frame data is malformed.
        invalid_goaway_data |

        % WINDOW_UPDATE frame data is malformed.
        invalid_window_update_data |

        % BLOCKED frame data is malformed.
        invalid_blocked_data |

        % STOP_WAITING frame data is malformed.
        invalid_stop_waiting_data |

        % PATH_CLOSE frame data is malformed.
        invalid_path_close_data |

        % ACK frame data is malformed.
        invalid_ack_data |

        % Version negotiation packet is malformed.
        invalid_version_negotiation_packet |

        % Public RST packet is malformed.
        invalid_public_rst_packet |

        % There was an error decrypting.
        decryption_failure |

        % There was an error encrypting.
        encryption_failure |

        % The packet exceeded kMaxPacketSize.
        packet_too_large |

        % The peer is going away.  May be a client or server.
        peer_going_away |

        % A stream ID was invalid.
        invalid_stream_id |

        % A priority was invalid.
        invalid_priority |

        % Too many streams already open.
        too_many_open_streams |

        % The peer created too many available streams.
        too_many_available_streams |

        % Received public reset for this connection.
        public_reset |

        % Invalid protocol version.
        invalid_version |

        % The Header ID for a stream was too far from the previous.
        invalid_header_id |

        % Negotiable parameter received during handshake had invalid value.
        invalid_negotiated_value |

        % There was an error decompressing data.
        decompression_failure |

        % The connection timed out due to no network activity.
        network_idle_timeout |

        % The connection timed out waiting for the handshake to complete.
        handshake_timeout |

        % There was an error encountered migrating addresses.
        error_migrating_address |

        % There was an error encountered migrating port only.
        error_migrating_port |

        % There was an error while writing to the socket.
        packet_write_error |

        % There was an error while reading from the socket.
        packet_read_error |

        % We received a STREAM_FRAME with no data and no fin flag set.
        empty_stream_frame_no_fin |

        % We received invalid data on the headers stream.
        invalid_headers_stream_data |

        % The peer received too much data, violating flow control.
        flow_control_received_too_much_data |

        % The peer sent too much data, violating flow control.
        flow_control_sent_too_much_data |

        % The peer received an invalid flow control window.
        flow_control_invalid_window |

        % The connection has been IP pooled into an existing connection.
        connection_ip_pooled |

        % The connection has too many outstanding sent packets.
        too_many_outstanding_sent_packets |

        % The connection has too many outstanding received packets.
        too_many_outstanding_received_packets |

        % The quic connection has been cancelled.
        connection_cancelled |

        % Disabled QUIC because of high packet loss rate.
        bad_packet_loss_rate |

        % Disabled QUIC because of too many PUBLIC_RESETs post handshake.
        public_resets_post_handshake |

        % Disabled QUIC because of too many timeouts with streams open.
        timeouts_with_open_streams |

        % Closed because we failed to serialize a packet.
        failed_to_serialize_packet |

        % QUIC timed out after too many RTOs.
        too_many_rtos |

        % Crypto errors.
        % Handshake failed.
        handshake_failed |

        % Handshake message contained out of order tags.
        crypto_tags_out_of_order |

        % Handshake message contained too many entries.
        crypto_too_many_entries |

        % Handshake message contained an invalid value length.
        crypto_invalid_value_length |

        % A crypto message was received after the handshake was complete.
        crypto_message_after_handshake_complete |

        % A crypto message was received with an illegal message tag.
        invalid_crypto_message_type |

        % A crypto message was received with an illegal parameter.
        invalid_crypto_message_parameter |

        % An invalid channel id signature was supplied.
        invalid_channel_id_signature |

        % A crypto message was received with a mandatory parameter missing.
        crypto_message_parameter_not_found |

        % A crypto message was received with a parameter that has no overlap
        % with the local parameter.
        crypto_message_parameter_no_overlap |

        % A crypto message was received that contained a parameter with too few
        % values.
        crypto_message_index_not_found |

        % A demand for an unsupport proof type was received.
        unsupported_proof_demand |

        % An internal error occurred in crypto processing.
        crypto_internal_error |

        % A crypto handshake message specified an unsupported version.
        crypto_version_not_supported |

        % A crypto handshake message resulted in a stateless reject.
        crypto_handshake_stateless_reject |

        % There was no intersection between the crypto primitives supported by the
        % peer and ourselves.
        crypto_no_support |

        % The server rejected our client hello messages too many times.
        crypto_too_many_rejects |

        % The client rejected the server's certificate chain or signature.
        proof_invalid |

        % A crypto message was received with a duplicate tag.
        crypto_duplicate_tag |

        % A crypto message was received with the wrong encryption level (i.e. it
        % should have been encrypted but was not.)
        crypto_encryption_level_incorrect |

        % The server config for a server has expired.
        crypto_server_config_expired |

        % We failed to setup the symmetric keys for a connection.
        crypto_symmetric_key_setup_failed |

        % A handshake message arrived, but we are still validating the
        % previous handshake message.
        crypto_message_while_validating_client_hello |

        % A server config update arrived before the handshake is complete.
        crypto_update_before_handshake_complete |

        % CHLO cannot fit in one packet.
        crypto_chlo_too_large |

        % This connection involved a version negotiation which appears to have been
        % tampered with.
        version_negotiation_mismatch |

        % Multipath errors.
        % Multipath is not enabled, but a packet with multipath flag on is received.
        bad_multipath_flag |

        % A path is supposed to exist but does not.
        multipath_path_does_not_exist |

        % A path is supposed to be active but is not.
        multipath_path_not_active |

        % IP address changed causing connection close.
        ip_address_changed |

        % Connection migration errors.
        % Network changed, but connection had no migratable streams.
        connection_migration_no_migratable_streams |

        % Connection changed networks too many times.
        connection_migration_too_many_changes |

        % Connection migration was attempted, but there was no new network to
        % migrate to.
        connection_migration_no_new_network |

        % Network changed, but connection had one or more non-migratable streams.
        connection_migration_non_migratable_stream |

        % Stream frames arrived too discontiguously so that stream sequencer buffer
        % maintains too many gaps.
        too_many_frame_gaps |

        % Sequencer buffer get into weird state where continuing read/write will lead
        % to crash.
        stream_sequencer_invalid_state |

        % Connection closed because of server hits max number of sessions allowed.
        too_many_sessions_on_server |

        {unknown, non_neg_integer()}).

-export_type([decoded_value/0]).

-type encoded_value() :: 0..96.
-export_type([encoded_value/0]).


-spec decode(encoded_value()) -> decoded_value().
decode(0) -> no_error;
decode(1) -> internal_error;
decode(2) -> stream_data_after_termination;
decode(3) -> invalid_packet_header;
decode(4) -> invalid_frame_data;
decode(48) -> missing_payload;
decode(5) -> invalid_fec_data;
decode(46) -> invalid_stream_data;
decode(87) -> overlapping_stream_data;
decode(61) -> unencrypted_stream_data;
decode(88) -> attempt_to_send_unencrypted_stream_data;
decode(89) -> maybe_corrupted_memory;
decode(77) -> unencrypted_fec_data;
decode(6) -> invalid_rst_stream_data;
decode(7) -> invalid_connection_close_data;
decode(8) -> invalid_goaway_data;
decode(57) -> invalid_window_update_data;
decode(58) -> invalid_blocked_data;
decode(60) -> invalid_stop_waiting_data;
decode(78) -> invalid_path_close_data;
decode(9) -> invalid_ack_data;
decode(10) -> invalid_version_negotiation_packet;
decode(11) -> invalid_public_rst_packet;
decode(12) -> decryption_failure;
decode(13) -> encryption_failure;
decode(14) -> packet_too_large;
decode(16) -> peer_going_away;
decode(17) -> invalid_stream_id;
decode(49) -> invalid_priority;
decode(18) -> too_many_open_streams;
decode(76) -> too_many_available_streams;
decode(19) -> public_reset;
decode(20) -> invalid_version;
decode(22) -> invalid_header_id;
decode(23) -> invalid_negotiated_value;
decode(24) -> decompression_failure;
decode(25) -> network_idle_timeout;
decode(67) -> handshake_timeout;
decode(26) -> error_migrating_address;
decode(86) -> error_migrating_port;
decode(27) -> packet_write_error;
decode(51) -> packet_read_error;
decode(50) -> empty_stream_frame_no_fin;
decode(56) -> invalid_headers_stream_data;
decode(59) -> flow_control_received_too_much_data;
decode(63) -> flow_control_sent_too_much_data;
decode(64) -> flow_control_invalid_window;
decode(62) -> connection_ip_pooled;
decode(68) -> too_many_outstanding_sent_packets;
decode(69) -> too_many_outstanding_received_packets;
decode(70) -> connection_cancelled;
decode(71) -> bad_packet_loss_rate;
decode(73) -> public_resets_post_handshake;
decode(74) -> timeouts_with_open_streams;
decode(75) -> failed_to_serialize_packet;
decode(85) -> too_many_rtos;
decode(28) -> handshake_failed;
decode(29) -> crypto_tags_out_of_order;
decode(30) -> crypto_too_many_entries;
decode(31) -> crypto_invalid_value_length;
decode(32) -> crypto_message_after_handshake_complete;
decode(33) -> invalid_crypto_message_type;
decode(34) -> invalid_crypto_message_parameter;
decode(52) -> invalid_channel_id_signature;
decode(35) -> crypto_message_parameter_not_found;
decode(36) -> crypto_message_parameter_no_overlap;
decode(37) -> crypto_message_index_not_found;
decode(94) -> unsupported_proof_demand;
decode(38) -> crypto_internal_error;
decode(39) -> crypto_version_not_supported;
decode(72) -> crypto_handshake_stateless_reject;
decode(40) -> crypto_no_support;
decode(41) -> crypto_too_many_rejects;
decode(42) -> proof_invalid;
decode(43) -> crypto_duplicate_tag;
decode(44) -> crypto_encryption_level_incorrect;
decode(45) -> crypto_server_config_expired;
decode(53) -> crypto_symmetric_key_setup_failed;
decode(54) -> crypto_message_while_validating_client_hello;
decode(65) -> crypto_update_before_handshake_complete;
decode(90) -> crypto_chlo_too_large;
decode(55) -> version_negotiation_mismatch;
decode(79) -> bad_multipath_flag;
decode(91) -> multipath_path_does_not_exist;
decode(92) -> multipath_path_not_active;
decode(80) -> ip_address_changed;
decode(81) -> connection_migration_no_migratable_streams;
decode(82) -> connection_migration_too_many_changes;
decode(83) -> connection_migration_no_new_network;
decode(84) -> connection_migration_non_migratable_stream;
decode(93) -> too_many_frame_gaps;
decode(95) -> stream_sequencer_invalid_state;
decode(96) -> too_many_sessions_on_server;
decode(Unknown) -> {unknown, Unknown}.

-spec encode(decoded_value()) -> encoded_value().
encode(no_error) -> 0;
encode(internal_error) -> 1;
encode(stream_data_after_termination) -> 2;
encode(invalid_packet_header) -> 3;
encode(invalid_frame_data) -> 4;
encode(missing_payload) -> 48;
encode(invalid_fec_data) -> 5;
encode(invalid_stream_data) -> 46;
encode(overlapping_stream_data) -> 87;
encode(unencrypted_stream_data) -> 61;
encode(attempt_to_send_unencrypted_stream_data) -> 88;
encode(maybe_corrupted_memory) -> 89;
encode(unencrypted_fec_data) -> 77;
encode(invalid_rst_stream_data) -> 6;
encode(invalid_connection_close_data) -> 7;
encode(invalid_goaway_data) -> 8;
encode(invalid_window_update_data) -> 57;
encode(invalid_blocked_data) -> 58;
encode(invalid_stop_waiting_data) -> 60;
encode(invalid_path_close_data) -> 78;
encode(invalid_ack_data) -> 9;
encode(invalid_version_negotiation_packet) -> 10;
encode(invalid_public_rst_packet) -> 11;
encode(decryption_failure) -> 12;
encode(encryption_failure) -> 13;
encode(packet_too_large) -> 14;
encode(peer_going_away) -> 16;
encode(invalid_stream_id) -> 17;
encode(invalid_priority) -> 49;
encode(too_many_open_streams) -> 18;
encode(too_many_available_streams) -> 76;
encode(public_reset) -> 19;
encode(invalid_version) -> 20;
encode(invalid_header_id) -> 22;
encode(invalid_negotiated_value) -> 23;
encode(decompression_failure) -> 24;
encode(network_idle_timeout) -> 25;
encode(handshake_timeout) -> 67;
encode(error_migrating_address) -> 26;
encode(error_migrating_port) -> 86;
encode(packet_write_error) -> 27;
encode(packet_read_error) -> 51;
encode(empty_stream_frame_no_fin) -> 50;
encode(invalid_headers_stream_data) -> 56;
encode(flow_control_received_too_much_data) -> 59;
encode(flow_control_sent_too_much_data) -> 63;
encode(flow_control_invalid_window) -> 64;
encode(connection_ip_pooled) -> 62;
encode(too_many_outstanding_sent_packets) -> 68;
encode(too_many_outstanding_received_packets) -> 69;
encode(connection_cancelled) -> 70;
encode(bad_packet_loss_rate) -> 71;
encode(public_resets_post_handshake) -> 73;
encode(timeouts_with_open_streams) -> 74;
encode(failed_to_serialize_packet) -> 75;
encode(too_many_rtos) -> 85;
encode(handshake_failed) -> 28;
encode(crypto_tags_out_of_order) -> 29;
encode(crypto_too_many_entries) -> 30;
encode(crypto_invalid_value_length) -> 31;
encode(crypto_message_after_handshake_complete) -> 32;
encode(invalid_crypto_message_type) -> 33;
encode(invalid_crypto_message_parameter) -> 34;
encode(invalid_channel_id_signature) -> 52;
encode(crypto_message_parameter_not_found) -> 35;
encode(crypto_message_parameter_no_overlap) -> 36;
encode(crypto_message_index_not_found) -> 37;
encode(unsupported_proof_demand) -> 94;
encode(crypto_internal_error) -> 38;
encode(crypto_version_not_supported) -> 39;
encode(crypto_handshake_stateless_reject) -> 72;
encode(crypto_no_support) -> 40;
encode(crypto_too_many_rejects) -> 41;
encode(proof_invalid) -> 42;
encode(crypto_duplicate_tag) -> 43;
encode(crypto_encryption_level_incorrect) -> 44;
encode(crypto_server_config_expired) -> 45;
encode(crypto_symmetric_key_setup_failed) -> 53;
encode(crypto_message_while_validating_client_hello) -> 54;
encode(crypto_update_before_handshake_complete) -> 65;
encode(crypto_chlo_too_large) -> 90;
encode(version_negotiation_mismatch) -> 55;
encode(bad_multipath_flag) -> 79;
encode(multipath_path_does_not_exist) -> 91;
encode(multipath_path_not_active) -> 92;
encode(ip_address_changed) -> 80;
encode(connection_migration_no_migratable_streams) -> 81;
encode(connection_migration_too_many_changes) -> 82;
encode(connection_migration_no_new_network) -> 83;
encode(connection_migration_non_migratable_stream) -> 84;
encode(too_many_frame_gaps) -> 93;
encode(stream_sequencer_invalid_state) -> 95;
encode(too_many_sessions_on_server) -> 96.
