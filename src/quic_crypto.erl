-module(quic_crypto).

-include("quic.hrl").
%-include("quic_crypto.hrl").
-include("quic_crypto_common_cert_substrings.hrl").
-include("quic_data_kv.hrl").
-include("quic_numeric.hrl").
-include("quic_packet.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([on_start/1]).
-export([on_diversification_nonce/2]).
-export([on_data_kv/2]).
-export([decrypt_packet_payload/4]).
-export([encrypt_packet_payload/4]).
-export([packet_encryption_overhead/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(SHA256_HASH_SIZE, 32).
-define(HKDF_KEY_SIZE, 16).
-define(HKDF_IV_SIZE, 4).
-define(AES_GCM_TAG_SIZE, 12).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(plain_encryption, {
          connection_id :: uint64()
         }).
-type plain_encryption() :: #plain_encryption{}.

-record(initial_encryption, {
          connection_id :: connection_id(),
          keys :: keys(),
          aead_algorithm :: known_aead_algorithm(),
          %have_encrypted_packets_been_received :: boolean(),
          has_diversified :: boolean(),
          params :: initial_encryption_params()
         }).
-type initial_encryption() :: #initial_encryption{}.

-record(forward_secure_encryption, {
          connection_id :: connection_id(),
          keys :: keys(),
          aead_algorithm :: known_aead_algorithm()
         }).
-type forward_secure_encryption() :: #forward_secure_encryption{}.

-record(initial_encryption_params, {
          key_exchange_algorithm :: known_key_exchange_algorithm(),
          server_nonce :: iodata(),
          client_nonce :: iodata(),
          client_private_key :: iodata(),
          client_public_key :: iodata(),
          shared_secret :: iodata(),
          encoded_chlo_data_kv :: iodata(),
          encoded_server_cfg :: iodata(),
          encoded_leaf_certificate :: iodata()
         }).
-type initial_encryption_params() :: #initial_encryption_params{}.

-record(keys, {
          client_write_key :: iodata(),
          server_write_key :: iodata(),
          client_iv :: iodata(),
          server_iv :: iodata()
         }).
-type keys() :: #keys{}.

-record(server_rej, {
          source_address_token :: binary(), % optional
          server_nonce :: binary(), % optional
          certificate_chain :: [public_key:pki_asn1_type(), ...],
          authenticity_proof :: binary(), % optional @TODO decode and handle?
          server_cfg :: server_cfg(), % optional
          encoded_server_cfg :: binary() % optional
         }).
-type server_rej() :: #server_rej{}.

-record(server_cfg, {
          config_id :: binary(), % 16 bytes
          key_exchange_algorithms :: [key_exchange_algorithm(), ...],
          aead_algorithms :: [aead_algorithm(), ...],
          public_values_map :: #{key_exchange_algorithm() => binary()},
          orbit :: binary(), % 8 bytes
          expiry_timestamp :: uint64(),
          versions :: [binary()]
         }).
-type server_cfg() :: #server_cfg{}.

-record(compressed_certificate_chain_entry, {
         }).
-type compressed_certificate_chain_entry() :: #compressed_certificate_chain_entry{}.

-record(cached_certificate_chain_entry, {
          hash :: binary() % 8 bytes
         }).
-type cached_certificate_chain_entry() :: #cached_certificate_chain_entry{}.

-record(common_certificate_chain_entry, {
          set_hash :: binary(), % 8 bytes
          index :: uint32()
         }).
-type common_certificate_chain_entry() :: #common_certificate_chain_entry{}.

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-type state() :: plain_encryption() | initial_encryption() | forward_secure_encryption().
-export_type([state/0]).

-type known_key_exchange_algorithm() :: curve25519. % | p256.
-type key_exchange_algorithm() :: known_key_exchange_algorithm() | {unknown, binary()}.

-type known_aead_algorithm() :: aes_gcm. %| salsa20_poly1305.
-type aead_algorithm() :: known_key_exchange_algorithm() | {unknown, binary()}.

-type certificate_chain_entry() :: (compressed_certificate_chain_entry() |
                                    cached_certificate_chain_entry() |
                                    common_certificate_chain_entry()).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

on_start(ConnectionId) ->
    InchoateDataKv = inchoate_data_kv(),
    [{change_state, #plain_encryption{ connection_id = ConnectionId }},
     {reply, {data_kv, InchoateDataKv}, [{version_header, ?QUIC_VERSION}]}].

on_diversification_nonce(DiversificationNonce, State) ->
    maybe_diversify(DiversificationNonce, State).

on_data_kv(DataKv, #plain_encryption{} = State)
  when DataKv#data_kv.tag =:= <<"REJ">> ->
    lager:debug("processing server rej"),
    ServerRej = decode_server_rej(DataKv),
    on_server_rej(ServerRej, State);
on_data_kv(DataKv, #initial_encryption{} = State)
  when DataKv#data_kv.tag =:= <<"SHLO">> ->
    lager:debug("processing server hello"),
    on_server_hello(DataKv, State).

decrypt_packet_payload(_PacketNumber, HeadersData, EncryptedPayload, State)
  when is_record(State, plain_encryption) ->
    <<Fnv1Hash:12/binary, Payload/binary>> = EncryptedPayload,
    ExpectedFnv1Hash = quic_util:hash_fnv1a_96([HeadersData, Payload]),
    ?ASSERT(Fnv1Hash =:= ExpectedFnv1Hash, invalid_unencrypted_packet),
    {Payload, State};
decrypt_packet_payload(PacketNumber, HeadersData, EncryptedPayload, State)
  when is_record(State, initial_encryption) ->
    % @TODO handle unencrypted packets that might arrive before first encrypted
    #initial_encryption{ aead_algorithm = AeadAlgorithm,
                         keys = Keys } = State,
    Result = try_decrypt_aead_packet_payload(
               PacketNumber, HeadersData, EncryptedPayload,
               AeadAlgorithm, Keys),
    ?ASSERT(Result =/= error, invalid_initial_encryption_packet),
    {Result, State};
decrypt_packet_payload(PacketNumber, HeadersData, EncryptedPayload, State)
  when is_record(State, forward_secure_encryption) ->
    #forward_secure_encryption{ aead_algorithm = AeadAlgorithm,
                                keys = Keys } = State,
    Result = try_decrypt_aead_packet_payload(
               PacketNumber, HeadersData, EncryptedPayload,
               AeadAlgorithm, Keys),
    ?ASSERT(Result =/= error, invalid_forward_secure_packet),
    {Result, State}.

encrypt_packet_payload(_PacketNumber, HeadersData, Payload, State)
  when is_record(State, plain_encryption) ->
    Fnv1Hash = quic_util:hash_fnv1a_96([HeadersData, Payload]),
    {[Fnv1Hash, Payload], State};
encrypt_packet_payload(PacketNumber, HeadersData, Payload, State)
  when is_record(State, initial_encryption) ->
    #initial_encryption{ aead_algorithm = AeadAlgorithm,
                         keys = Keys } = State,
    EncryptedPayload =
        encrypt_aead_packet_payload(PacketNumber, HeadersData,
                                    Payload, AeadAlgorithm, Keys),
    {EncryptedPayload, State};
encrypt_packet_payload(PacketNumber, HeadersData, Payload, State)
  when is_record(State, forward_secure_encryption) ->
    #forward_secure_encryption{ aead_algorithm = AeadAlgorithm,
                                keys = Keys } = State,
    EncryptedPayload =
        encrypt_aead_packet_payload(PacketNumber, HeadersData,
                                    Payload, AeadAlgorithm, Keys),
    {EncryptedPayload, State}.

packet_encryption_overhead(#plain_encryption{}) ->
    12; % 12 bytes for truncated FNV1a-128 hash
packet_encryption_overhead(#initial_encryption{ aead_algorithm = AeadAlgorithm }) ->
    aead_encryption_overhead(AeadAlgorithm);
packet_encryption_overhead(#forward_secure_encryption{ aead_algorithm = AeadAlgorithm }) ->
    aead_encryption_overhead(AeadAlgorithm).

%% ------------------------------------------------------------------
%% Initial encryption
%% ------------------------------------------------------------------

initial_encryption(ConnectionId, AeadAlgorithm, InitialEncryptionParams) ->
    #initial_encryption_params{
       server_nonce = ServerNonce,
       client_nonce = ClientNonce,
       shared_secret = SharedSecret,
       encoded_chlo_data_kv = EncodedChloDataKv,
       encoded_server_cfg = EncodedServerCfg,
       encoded_leaf_certificate = EncodedLeafCertificate } = InitialEncryptionParams,

    ?ASSERT(EncodedServerCfg =/= undefined, missing_server_cfg),

    % for extraction
    Salt = [ClientNonce, quic_util:coalesce(ServerNonce, "")],

    % for expansion
    HkdfSuffix = [16#00,
                  quic_packet:encode_connection_id(ConnectionId),
                  EncodedChloDataKv,
                  EncodedServerCfg,
                  EncodedLeafCertificate],
    Info = ["QUIC key expansion", HkdfSuffix],

    SubkeySecretSize = 4,
    MaterialLength = (?HKDF_KEY_SIZE + % client key
                      ?HKDF_KEY_SIZE + % server key
                      ?HKDF_IV_SIZE  + % client iv
                      ?HKDF_IV_SIZE  + % server iv
                      SubkeySecretSize),

    Prk = hkdf:extract(sha256, Salt, SharedSecret),

    Output = hkdf:expand(sha256, Prk, iolist_to_binary(Info), MaterialLength),
    <<ClientWriteKey:?HKDF_KEY_SIZE/binary,
      ServerWriteKey:?HKDF_KEY_SIZE/binary,
      ClientIv:?HKDF_IV_SIZE/binary,
      ServerIv:?HKDF_IV_SIZE/binary,
      _Subkey:SubkeySecretSize/binary>> = Output,

    Keys = #keys{
              client_write_key = ClientWriteKey,
              server_write_key = ServerWriteKey,
              client_iv = ClientIv,
              server_iv = ServerIv },

    #initial_encryption{
       connection_id = ConnectionId,
       keys = Keys,
       aead_algorithm = AeadAlgorithm,
       %have_encrypted_packets_been_received = false,
       has_diversified = false,
       params = InitialEncryptionParams }.


%% ------------------------------------------------------------------
%% Key diversification
%% ------------------------------------------------------------------

maybe_diversify(undefined, State) ->
    State;
maybe_diversify(_, #initial_encryption{ has_diversified = true } = State) ->
    State;
maybe_diversify(_, #forward_secure_encryption{} = State) ->
    State;
maybe_diversify(<<DiversificationNonce:32/binary>>, #initial_encryption{} = State) ->
    Keys = State#initial_encryption.keys,
    #keys{ server_write_key = ServerWriteKey,
           server_iv = ServerIv } = Keys,

    Secret = [ServerWriteKey, ServerIv],
    Salt = DiversificationNonce,
    Info = "QUIC key diversification",

    MaterialLength = (?HKDF_KEY_SIZE + % server key
                      ?HKDF_IV_SIZE),  % server iv

    Prk = hkdf:extract(sha256, Salt, Secret),
    Output = hkdf:expand(sha256, Prk, iolist_to_binary(Info), MaterialLength),
    <<NewServerWriteKey:?HKDF_KEY_SIZE/binary,
      NewServerIv:?HKDF_IV_SIZE/binary>> = Output,

    NewKeys = Keys#keys{
                server_write_key = NewServerWriteKey,
                server_iv = NewServerIv },
    State#initial_encryption{ has_diversified = true,
                              keys = NewKeys }.

%% ------------------------------------------------------------------
%% inchoate
%% ------------------------------------------------------------------

inchoate_data_kv() ->
    % @TODO: actually scale accordingly (min CHLO size is 1024, apparently?)
    TaggedValues = #{"PAD" => [0 || _ <- lists:seq(1, 1024)],
                     "SNI" => "www.example.com",
                     "VER" => ?QUIC_VERSION,
                     "PDMD" => "X509"},

    #data_kv{ tag = <<"CHLO">>,
              tagged_values = TaggedValues }.

%% ------------------------------------------------------------------
%% chlo
%% ------------------------------------------------------------------

chlo_data_kv(ServerRej, PickedKeyExchangeAlgorithm, ClientNonce, ClientPublicKey) ->
    #server_rej{ server_cfg = (#server_cfg{} = ServerCfg) } = ServerRej,

    PickedAeadAlgorithm =
        hd(lists:filter(fun is_known_algorithm/1,
                        ServerCfg#server_cfg.aead_algorithms)),

    LeafCertificate = hd(ServerRej#server_rej.certificate_chain),
    EncodedLeafCertificate = public_key:pkix_encode('Certificate', LeafCertificate, plain),
    EncodedLeafCertificateFnv1a64 = hash:fnv64a(EncodedLeafCertificate),
    BinEncodedLeafCertificateFnv1a64 = quic_util:encode_uint(EncodedLeafCertificateFnv1a64, 8),

    % @TODO: actually scale accordingly (min CHLO size is 1024, apparently?)
    TaggedValues = #{"PAD" => [0 || _ <- lists:seq(1, 800)],
                     "SNI" => "www.example.com",
                     "VER" => ?QUIC_VERSION,
                     "PDMD" => "X509",
                     "SCID" => ServerCfg#server_cfg.config_id,
                     "AEAD" => encode_aead_algorithm(PickedAeadAlgorithm),
                     "KEXS" => encode_key_exchange_algorithm(PickedKeyExchangeAlgorithm),
                     "NONC" => ClientNonce,
                     "SNO" => ServerRej#server_rej.server_nonce,
                     "PUBS" => ClientPublicKey,
                     "STK" => ServerRej#server_rej.source_address_token,
                     % leaf certificate thing
                     "XLCT" => BinEncodedLeafCertificateFnv1a64,
                     % "idle connection state", required; @TODO define it properly
                     "ICSL" => quic_util:encode_uint(5, 4)},

    #data_kv{ tag = <<"CHLO">>,
              tagged_values = TaggedValues }.

-spec is_known_algorithm(key_exchange_algorithm() | aead_algorithm()) -> boolean().
is_known_algorithm(V) -> is_atom(V).

-spec generate_client_nonce(binary()) -> iodata().
generate_client_nonce(ServerOrbitValue) ->
    Now = os:system_time(seconds),
    [<<Now:4/big-unsigned-integer-unit:8>>,
     ServerOrbitValue,
     crypto:strong_rand_bytes(20)].

%% ------------------------------------------------------------------
%% server hello
%% ------------------------------------------------------------------

on_server_hello(#data_kv{ tag = <<"SHLO">>,
                          tagged_values = TaggedValues },
                #initial_encryption{} = State) ->

    #initial_encryption{
       connection_id = ConnectionId,
       aead_algorithm = AeadAlgorithm,
       params = Params } = State,
    #initial_encryption_params{
       key_exchange_algorithm = KeyExchangeAlgorithm,
       client_private_key = ClientPrivateKey,
       client_nonce = ClientNonce,
       encoded_chlo_data_kv = EncodedChloDataKv,
       encoded_server_cfg = EncodedServerCfg,
       encoded_leaf_certificate = EncodedLeafCertificate } = Params,

    NewServerNonce = maps:get(<<"SNO">>, TaggedValues),
    NewServerPublicValue = maps:get(<<"PUBS">>, TaggedValues),
    NewSharedKey = generate_key_exchange_params(KeyExchangeAlgorithm, ClientPrivateKey,
                                                NewServerPublicValue),

    % for extraction
    Salt = [ClientNonce, NewServerNonce],

    % for expansion
    HkdfSuffix = [16#00,
                  quic_packet:encode_connection_id(ConnectionId),
                  EncodedChloDataKv,
                  EncodedServerCfg,
                  EncodedLeafCertificate],
    Info = ["QUIC forward secure key expansion", HkdfSuffix],

    SubkeySecretSize = 4,
    MaterialLength = (?HKDF_KEY_SIZE + % client key
                      ?HKDF_KEY_SIZE + % server key
                      ?HKDF_IV_SIZE  + % client iv
                      ?HKDF_IV_SIZE  + % server iv
                      SubkeySecretSize),

    Prk = hkdf:extract(sha256, Salt, NewSharedKey),

    Output = hkdf:expand(sha256, Prk, iolist_to_binary(Info), MaterialLength),
    <<ClientWriteKey:?HKDF_KEY_SIZE/binary,
      ServerWriteKey:?HKDF_KEY_SIZE/binary,
      ClientIv:?HKDF_IV_SIZE/binary,
      ServerIv:?HKDF_IV_SIZE/binary,
      _Subkey:SubkeySecretSize/binary>> = Output,

    NewKeys = #keys{
                 client_write_key = ClientWriteKey,
                 server_write_key = ServerWriteKey,
                 client_iv = ClientIv,
                 server_iv = ServerIv },

    [{change_state, #forward_secure_encryption{
                       connection_id = ConnectionId,
                       keys = NewKeys,
                       aead_algorithm = AeadAlgorithm }}].

%% ------------------------------------------------------------------
%% server REJ
%% ------------------------------------------------------------------

on_server_rej(ServerRej, PlainEncryption) ->
    ConnectionId = PlainEncryption#plain_encryption.connection_id,
    ServerCfg = ServerRej#server_rej.server_cfg,
    #server_cfg{ public_values_map = ServerPublicValuesMap,
                 key_exchange_algorithms = KeyExchangeAlgorithms,
                 aead_algorithms = AeadAlgorithms } = ServerCfg,

    PickedKeyExchangeAlgorithm = hd(lists:filter(fun is_known_algorithm/1, KeyExchangeAlgorithms)),
    PickedAeadAlgorithm= hd(lists:filter(fun is_known_algorithm/1, AeadAlgorithms)),

    PickedPublicValue = maps:get(PickedKeyExchangeAlgorithm, ServerPublicValuesMap),
    ClientNonce = generate_client_nonce(ServerCfg#server_cfg.orbit),
    {ClientPrivateKey, ClientPublicKey,
     SharedSecret} = generate_key_exchange_params(PickedKeyExchangeAlgorithm, PickedPublicValue),

    LeafCertificate = hd(ServerRej#server_rej.certificate_chain),
    EncodedLeafCertificate = public_key:pkix_encode('Certificate', LeafCertificate, plain),

    ChloDataKv = chlo_data_kv(ServerRej, PickedKeyExchangeAlgorithm, ClientNonce, ClientPublicKey),
    EncodedChloDataKv = quic_data_kv:encode(ChloDataKv),

    InitialEncryptionParams =
        #initial_encryption_params{
           key_exchange_algorithm = PickedKeyExchangeAlgorithm,
           server_nonce = ServerRej#server_rej.server_nonce,
           client_nonce = ClientNonce,
           client_private_key = ClientPrivateKey,
           client_public_key = ClientPublicKey,
           shared_secret = SharedSecret,
           encoded_chlo_data_kv = EncodedChloDataKv,
           encoded_server_cfg = ServerRej#server_rej.encoded_server_cfg,
           encoded_leaf_certificate = EncodedLeafCertificate },

    [{reply, {data_payload, EncodedChloDataKv}},
     {change_state, initial_encryption(ConnectionId, PickedAeadAlgorithm, InitialEncryptionParams)}].

-spec decode_server_rej(data_kv()) -> server_rej().
decode_server_rej(#data_kv{ tag = <<"REJ">>,
                            tagged_values = TaggedValues }) ->

    {ServerCfg, OriginalEncodedServerCfg} =
        case maps:find(<<"SCFG">>, TaggedValues) of
            error ->
                {undefined, undefined};
            {ok, EncodedServerCfg} ->
                {decode_server_cfg(quic_data_kv:decode(EncodedServerCfg)),
                 EncodedServerCfg}
        end,

    SourceAddresstoken = maps:get(<<"STK">>, TaggedValues, undefined),
    ServerNonce = maps:get(<<"SNO">>, TaggedValues, undefined),

    CertificateChain = case maps:find(<<"CRTÿ">>, TaggedValues) of
                           error -> undefined;
                           {ok, EncodedCertificateChain} ->
                               decode_certificate_chain(EncodedCertificateChain)
                       end,

    AuthenticityProof = maps:get(<<"PROF">>, TaggedValues, undefined),

    #server_rej{
       source_address_token = SourceAddresstoken,
       server_nonce = ServerNonce,
       certificate_chain = CertificateChain,
       authenticity_proof = AuthenticityProof,
       server_cfg = ServerCfg,
       encoded_server_cfg = OriginalEncodedServerCfg }.

-spec decode_server_cfg(data_kv()) -> server_cfg().
decode_server_cfg(#data_kv{ tag = <<"SCFG">>,
                            tagged_values = TaggedValues }) ->

    (<<_:16/binary>> = ConfigId) =
        maps:get(<<"SCID">>, TaggedValues),

    ([_|_] = KeyExchangeAlgorithms) =
        lists:map(fun decode_key_exchange_algorithm/1,
                  quic_data_kv:decode_tag_list(
                    maps:get(<<"KEXS">>, TaggedValues) )),

    ([_|_] = AeadAlgorithms) =
        lists:map(fun decode_aead_algorithm/1,
                  quic_data_kv:decode_tag_list(
                    maps:get(<<"AEAD">>, TaggedValues) )),

    ([_|_] = PublicValues) =
        decode_public_values(
          maps:get(<<"PUBS">>, TaggedValues)),
    PublicValuesMap = maps:from_list( lists:zip(KeyExchangeAlgorithms, PublicValues) ),

    (<<_:8, _/binary>> = Orbit) =
        maps:get(<<"OBIT">>, TaggedValues),

    <<ExpiryTimestamp:8/little-unsigned-integer-unit:8>> =
        maps:get(<<"EXPY">>, TaggedValues),

    % @todo: this seems to be missing?!
    ([_|_] = Versions) =
        quic_util:exact_binary_chunks(
          maps:get(<<"VER">>, TaggedValues, <<"todo">>), 4),

    #server_cfg{
       config_id = ConfigId,
       key_exchange_algorithms = KeyExchangeAlgorithms,
       aead_algorithms = AeadAlgorithms,
       public_values_map = PublicValuesMap,
       expiry_timestamp = ExpiryTimestamp,
       versions = Versions,
       orbit = Orbit }.

-spec decode_key_exchange_algorithm(binary()) -> key_exchange_algorithm().
decode_key_exchange_algorithm(<<"C255">>) -> curve25519;
%decode_key_exchange_algorithm(<<"P256">>) -> p256;
decode_key_exchange_algorithm(Unknown) -> {unknown, Unknown}.

-spec encode_key_exchange_algorithm(known_key_exchange_algorithm()) -> binary().
encode_key_exchange_algorithm(curve25519) -> <<"C255">>.
%encode_key_exchange_algorithm(p256) -> <<"P256">>.

-spec decode_aead_algorithm(binary()) -> aead_algorithm().
decode_aead_algorithm(<<"AESG">>) -> aes_gcm;
%decode_aead_algorithm(<<"S20P">>) -> salsa20_poly1305;
decode_aead_algorithm(Unknown) -> {unknown, Unknown}.

-spec encode_aead_algorithm(known_aead_algorithm()) -> binary().
encode_aead_algorithm(aes_gcm) -> <<"AESG">>.
%encode_aead_algorithm(salsa20_poly1305) -> <<"S20P">>.


-spec decode_public_values(binary()) -> [binary()].
decode_public_values(<<Size:3/little-unsigned-integer-unit:8,
                       PublicValue:Size/binary,
                       RemainingData/binary>>) ->
    [PublicValue | decode_public_values(RemainingData)];
decode_public_values(<<>>) ->
    [].

-spec decode_certificate_chain(binary()) -> [public_key:pki_asn1_type(), ...].
decode_certificate_chain(ChunkA) ->
    {ChunkB, Entries} = decode_certificate_chain_entries(ChunkA, []),
    ?ASSERT(Entries =/= [], empty_certificate_chains_unsupported),

    <<UncompressedLength:4/little-unsigned-integer-unit:8,
      GzipData/binary>> = ChunkB,
    Data = iolist_to_binary(
             quic_util:zlib_uncompress(GzipData, ?COMMON_CERT_SUBSTRINGS)),

    ?ASSERT(UncompressedLength >= iolist_size(Data),
            {mismatch_in_compressed_certificate_chain_size,
             [{expected, UncompressedLength},
              {actual, iolist_size(Data)}]}),

    BundledCertificates = decode_bundled_certificates(Data),
    {Certificates, []} =
        lists:mapfoldl(
          fun (#cached_certificate_chain_entry{}, _Acc) ->
                  exit(cached_certificate_chain_entries_unsupported);
              (#common_certificate_chain_entry{}, _Acc) ->
                  exit(common_certificate_chain_entries_unsupported);
              (#compressed_certificate_chain_entry{}, [BundledCertificate | Next]) ->
                  {BundledCertificate, Next}
          end,
          BundledCertificates,
          Entries),
    Certificates.

-spec decode_certificate_chain_entries(binary(), [certificate_chain_entry()])
        -> [certificate_chain_entry(), ...].
decode_certificate_chain_entries(<<0:8, RemainingData/binary>>, Acc) ->
    % end of list
    {RemainingData, lists:reverse(Acc)};
decode_certificate_chain_entries(<<1:8, RemainingData/binary>>, Acc) ->
    % compressed entry
    Entry = #compressed_certificate_chain_entry{},
    decode_certificate_chain_entries(RemainingData, [Entry | Acc]);
decode_certificate_chain_entries(<<2:8, Hash:8/binary, RemainingData/binary>>, Acc) ->
    % cached entry
    Entry = #cached_certificate_chain_entry{ hash = Hash },
    decode_certificate_chain_entries(RemainingData, [Entry | Acc]);
decode_certificate_chain_entries(<<3:8, SetHash:8/binary, Index:4/little-unsigned-integer-unit:8,
                                   RemainingData/binary>>, Acc) ->
    % common certificate chain entry
    Entry = #common_certificate_chain_entry{ set_hash = SetHash,
                                             index = Index },
    decode_certificate_chain_entries(RemainingData, [Entry | Acc]).

-spec decode_bundled_certificates(binary()) -> [public_key:pki_asn1_type()].
decode_bundled_certificates(<<>>) ->
    [];
decode_bundled_certificates(<<EncodedEntrySize:4/little-unsigned-integer-unit:8,
                              EncodedEntry:EncodedEntrySize/binary,
                              RemainingData/binary>>) ->
    Entry = public_key:pkix_decode_cert(EncodedEntry, plain),
    [Entry | decode_bundled_certificates(RemainingData)].

%% ------------------------------------------------------------------
%% Key exchange
%% ------------------------------------------------------------------

-spec generate_key_exchange_params(known_key_exchange_algorithm(), ServerPublicValue :: binary())
        -> {MyPrivateKey :: binary(), MyPublicKey :: binary(), SharedSecret :: binary()}.
generate_key_exchange_params(KeyExchangeAlgorithm, ServerPublicValue) ->
    {MyPrivateKey, MyPublicKey} = curve25519:key_pair(),
    SharedSecret = generate_key_exchange_params(KeyExchangeAlgorithm, MyPrivateKey, ServerPublicValue),
    {MyPrivateKey, MyPublicKey, SharedSecret}.

-spec generate_key_exchange_params(known_key_exchange_algorithm(),
                                   MyPrivateKey :: binary(),
                                   ServerPublicValue :: binary())
        -> SharedSecret :: binary().
generate_key_exchange_params(curve25519, MyPrivateKey, ServerPublicValue) ->
    curve25519:make_shared(ServerPublicValue, MyPrivateKey).

%% ------------------------------------------------------------------
%% AEAD for packets
%% ------------------------------------------------------------------

try_decrypt_aead_packet_payload(PacketNumber, HeadersData, EncryptedPayload, AeadAlgorithm, Keys)
  when AeadAlgorithm =:= aes_gcm ->
    AssociatedData = HeadersData,
    ServerWriteKey = Keys#keys.server_write_key,
    ServerIv = Keys#keys.server_iv,
    IV = <<ServerIv:4/binary, PacketNumber:8/little-unsigned-integer-unit:8>>,
    CipherTextLength = byte_size(EncryptedPayload) - ?AES_GCM_TAG_SIZE,
    <<CipherText:CipherTextLength/binary, CipherTag:?AES_GCM_TAG_SIZE/binary>> = EncryptedPayload,
    % @TODO: make it work in Erlang pre-19? pre-18 didn't have aes-gcm back then,
    % and r18 can't deal with tag sizes other than 16
    crypto:block_decrypt(AeadAlgorithm, ServerWriteKey, IV,
                         {AssociatedData, CipherText, CipherTag}).

encrypt_aead_packet_payload(PacketNumber, HeadersData, Payload, AeadAlgorithm, Keys)
  when AeadAlgorithm =:= aes_gcm ->
    AssociatedData = HeadersData,
    ClientWriteKey = Keys#keys.client_write_key,
    ClientIv = Keys#keys.client_iv,
    IV = <<ClientIv:4/binary, PacketNumber:8/little-unsigned-integer-unit:8>>,
    {CipherText, CipherTag} =
        crypto:block_encrypt(AeadAlgorithm, ClientWriteKey, IV,
                             {AssociatedData, Payload, ?AES_GCM_TAG_SIZE}),
    [CipherText, CipherTag].

aead_encryption_overhead(aes_gcm) ->
    ?AES_GCM_TAG_SIZE.
