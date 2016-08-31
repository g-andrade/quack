-module(quic_packet).

-include("quic.hrl").
-include("quic_packet.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([packet_number/1]).
-export([decode/3]).
-export([encode/3]).
-export([encode_connection_id/1]).

%% ------------------------------------------------------------------
%% Macro definitions
%% ------------------------------------------------------------------

-define(MAX_IPV4_PACKET_SIZE, 1350).
-define(MAX_IPV6_PACKET_SIZE, 1370).

%% ------------------------------------------------------------------
%% Getters
%% ------------------------------------------------------------------

-spec packet_number(quic_packet()) -> packet_number() | undefined.
packet_number(#public_reset_packet{}) ->
    undefined;
packet_number(#version_negotiation_packet{}) ->
    undefined;
packet_number(#regular_packet{ packet_number = PacketNumber }) ->
    PacketNumber.

%% ------------------------------------------------------------------
%% General encoding / decoding
%% ------------------------------------------------------------------

decode(<<PublicHeader:1/binary, RemainingData/binary>>, Origin, CryptoShadowState) ->
    <<0:1, % unused, must be zero
      _:1, % reserved for multipath use
      PacketNumberEncoding:2,
      ConnectionIdFlag:1,
      DiversificationNonceFlag:1,
      ResetFlag:1,
      VersionFlag:1>> = PublicHeader,

    PublicFlags = #public_flags{ version = VersionFlag,
                                 reset = ResetFlag,
                                 diversification_nonce = DiversificationNonceFlag,
                                 connection_id = ConnectionIdFlag,
                                 packet_number_encoding = PacketNumberEncoding },
    decode(RemainingData, Origin, PublicFlags, PublicHeader, CryptoShadowState).


encode(#public_reset_packet{} = Packet, _Origin, _CryptoShadowState) ->
    Flags = (2#00000010 bor % reset flag
             2#00001000),   % connection id flag
    [Flags,
     encode_connection_id(Packet#public_reset_packet.connection_id),
     "PRST",
     quic_data_kv:encode_tagged_values(Packet#public_reset_packet.tagged_values)];

encode(#version_negotiation_packet{ supported_versions = [_|_] } = Packet, _Origin, _CryptoShadowState) ->
    Flags = (2#00000001 bor % version flag
             2#00001000),   % connection id flag
    [Flags,
     encode_connection_id(Packet#version_negotiation_packet.connection_id),
     [encode_version(Version) || Version <- Packet#version_negotiation_packet.supported_versions]];

encode(#regular_packet{} = Packet, _Origin, CryptoShadowState) ->
    PacketNumber = Packet#regular_packet.packet_number,

    {EncodedConnectionId, ConnectionIdFlag} =
        maybe_encode_connection_id(Packet#regular_packet.connection_id),
    {EncodedVersion, VersionFlag} =
        maybe_encode_version(Packet#regular_packet.version),
    {EncodedDiversificationNonce, DiversificationNonceFlag} =
        maybe_encode_diversification_nonce(Packet#regular_packet.diversification_nonce),
    {EncodedPacketNumber, PacketNumberEncoding} =
        quic_proto_varint:encode_u48(PacketNumber),
    EncodedFrames =
        quic_frame:encode_frames(Packet#regular_packet.frames,
                                 PacketNumber, PacketNumberEncoding),

    EncodedFlags =
        lists:foldl(fun erlang:'bor'/2, 0,
                    [ConnectionIdFlag bsl 3,
                     VersionFlag,
                     DiversificationNonceFlag bsl 2,
                     PacketNumberEncoding bsl 4]),
    EncodedHeader =
        [EncodedFlags,
         EncodedConnectionId,
         EncodedVersion,
         EncodedDiversificationNonce,
         EncodedPacketNumber],

    PreliminaryEncodedPacketSize = (iolist_size(EncodedHeader) +
                                    iolist_size(EncodedFrames) +
                                    quic_crypto:packet_encryption_overhead(CryptoShadowState)),

    ?ASSERT(PreliminaryEncodedPacketSize =< ?MAX_IPV4_PACKET_SIZE,
            {packet_too_big, PreliminaryEncodedPacketSize, Packet}),

    PaddedEncodedFrames = maybe_pad_frames(?MAX_IPV4_PACKET_SIZE, PreliminaryEncodedPacketSize,
                                           EncodedFrames, PacketNumber, PacketNumberEncoding),

    EncryptedPayload =
        quic_crypto:encrypt_packet_payload(PacketNumber, EncodedHeader,
                                           PaddedEncodedFrames, CryptoShadowState),
    [EncodedHeader, EncryptedPayload].

%% ------------------------------------------------------------------
%% Quic packet handling
%% ------------------------------------------------------------------

decode(ChunkA, _Origin, #public_flags{ reset = 1, connection_id = 1 },
       _OriginalPublicHeader, CryptoShadowState) ->
    % public reset packet
    {ChunkB, ConnectionId} = decode_connection_id(ChunkA),
    <<"PRST", EncodedTaggedValues/binary>> = ChunkB,
    {TaggedValues, <<>>} = quic_data_kv:decode_tagged_values(EncodedTaggedValues),
    {#public_reset_packet{ connection_id = ConnectionId,
                           tagged_values = TaggedValues },
     CryptoShadowState};

decode(ChunkA, server, #public_flags{ version = 1, connection_id = 1 },
       _OriginalPublicHeader, CryptoShadowState)  ->
    % server negotiation packet
    {ChunkB, ConnectionId} = decode_connection_id(ChunkA),
    ([_|_] = SupportedVersions) = quic_util:exact_binary_chunks(ChunkB, 4),
    {#version_negotiation_packet{ connection_id = ConnectionId,
                                  supported_versions = SupportedVersions },
     CryptoShadowState};

decode(ChunkA, _Origin, PublicFlags,
       OriginalPublicHeader, CryptoShadowStateA) ->
    % regular_packet packet
    lager:debug("parsing packet with public_flags ~p", [lager:pr(PublicFlags, ?MODULE)]),
    #public_flags{ version = VersionFlag,
                   diversification_nonce = DiversificationNonceFlag,
                   connection_id = ConnectionIdFlag,
                   packet_number_encoding = PacketNumberEncoding } = PublicFlags,

    {ChunkB, ConnectionId} = maybe_decode_connection_id(ChunkA, ConnectionIdFlag),
    {ChunkC, Version} = maybe_decode_version(ChunkB, VersionFlag),
    {ChunkD, DiversificationNonce} = maybe_decode_diversification_nonce(ChunkC, DiversificationNonceFlag),
    {ChunkE, PacketNumber} = quic_proto_varint:decode_u48(ChunkD, PacketNumberEncoding),
    lager:debug("got packet with packet_number ~p", [PacketNumber]),

    BodyPrecedingData = [OriginalPublicHeader,
                         binary:part(ChunkA, 0, byte_size(ChunkA) - byte_size(ChunkE))],
    Body = ChunkE,

    CryptoShadowStateB = quic_crypto:on_diversification_nonce(DiversificationNonce, CryptoShadowStateA),
    {DecryptedBody, CryptoShadowStateC} =
        quic_crypto:decrypt_packet_payload(PacketNumber, BodyPrecedingData, Body, CryptoShadowStateB),

    Frames = quic_frame:decode_frames(DecryptedBody, PacketNumber, PacketNumberEncoding),

    {#regular_packet{ connection_id = ConnectionId,
                      version = Version,
                      diversification_nonce = DiversificationNonce,
                      packet_number = PacketNumber,
                      frames = Frames },
     CryptoShadowStateC}.

%% ------------------------------------------------------------------
%% Public header - connection id handling
%% ------------------------------------------------------------------

decode_connection_id(<<ConnectionId:8/little-unsigned-integer-unit:8, Data/binary>>) ->
    {Data, ConnectionId}.

encode_connection_id(ConnectionId) ->
    <<ConnectionId:8/little-unsigned-integer-unit:8>>.

maybe_decode_connection_id(Data, 0) ->
    {Data, undefined};
maybe_decode_connection_id(Data, 1) ->
    decode_connection_id(Data).

maybe_encode_connection_id(undefined) ->
    {"", 0};
maybe_encode_connection_id(ConnectionId) ->
    {encode_connection_id(ConnectionId), 1}.

%% ------------------------------------------------------------------
%% Public header - version handling
%% ------------------------------------------------------------------

decode_version(<<Version:4/binary, Data/binary>>) ->
    {Data, Version}.

encode_version(Version) ->
    <<Version:4/binary>>.

maybe_decode_version(Data, 0) ->
    {Data, undefined};
maybe_decode_version(Data, 1) ->
    decode_version(Data).

maybe_encode_version(undefined) ->
    {"", 0};
maybe_encode_version(Version) ->
    {encode_version(Version), 1}.

%% ------------------------------------------------------------------
%% Public header - diversification nonce handling
%% ------------------------------------------------------------------

decode_diversification_nonce(<<DiversificationNonce:32/binary, Data/binary>>) ->
    {Data, DiversificationNonce}.

encode_diversification_nonce(DiversificationNonce) ->
    <<DiversificationNonce:32/binary>>.

maybe_decode_diversification_nonce(Data, 0) ->
    {Data, undefined};
maybe_decode_diversification_nonce(Data, 1) ->
    decode_diversification_nonce(Data).

maybe_encode_diversification_nonce(undefined) ->
    {"", 0};
maybe_encode_diversification_nonce(DiversificationNonce) ->
    {encode_diversification_nonce(DiversificationNonce), 1}.

%% ------------------------------------------------------------------
%% Padding
%% ------------------------------------------------------------------

maybe_pad_frames(MaxPacketsize, PredictedPacketSize, EncodedFrames,
                 PacketNumber, PacketNumberEncoding) ->
    MissingSize = MaxPacketsize - PredictedPacketSize,
    case MissingSize > 0 of
        false ->
            EncodedFrames;
        true ->
            quic_frame:append_padding_to_encoded_frames(
              EncodedFrames, MissingSize, PacketNumber,
              PacketNumberEncoding)
    end.
