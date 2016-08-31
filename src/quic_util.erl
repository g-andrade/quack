-module(quic_util).

-include("quic.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([binary_chunks/2]).
-export([exact_binary_chunks/2]).
-export([bit_to_boolean/1]).
-export([boolean_to_bit/1]).
-export([encode_uint/2]).
-export([hash_fnv1a_96/1]).
-export([zlib_uncompress/2]).
-export([coalesce/2]).
-export([binary_to_hex/1]).
-export([filtermapfoldl/3]).
-export([now_us/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec binary_chunks(Blob :: binary(), Size :: pos_integer()) -> [binary()].
binary_chunks(Data, Size) when byte_size(Data) >= Size ->
    <<Chunk:Size/binary, RemainingData/binary>> = Data,
    [Chunk | binary_chunks(RemainingData, Size)];
binary_chunks(<<RemainingData/binary>>, _Size) ->
    [RemainingData].

-spec exact_binary_chunks(Blob :: binary(), Size :: pos_integer()) -> [binary()].
exact_binary_chunks(<<>>, _Size) ->
    [];
exact_binary_chunks(Data, Size) ->
    <<Chunk:Size/binary, RemainingData/binary>> = Data,
    [Chunk | exact_binary_chunks(RemainingData, Size)].

bit_to_boolean(0) -> false;
bit_to_boolean(1) -> true.

boolean_to_bit(false) -> 0;
boolean_to_bit(true) -> 1.

encode_uint(Value, Size) ->
    <<Value:Size/little-unsigned-integer-unit:8>>.

-spec hash_fnv1a_96(iodata()) -> binary().
hash_fnv1a_96(Data) ->
    % Based on https://groups.google.com/a/chromium.org/forum/#!topic/proto-quic/VpuIIe0WL3U
    Hash128 = hash:fnv128a(iolist_to_binary(Data)),
    <<Truncated:12/binary, _:4/binary>> = encode_uint(Hash128, 16),
    Truncated.

-spec zlib_uncompress(Compressed :: binary(), Dictionary :: binary())
        -> Uncompressed :: binary().
zlib_uncompress(Compressed, Dictionary) ->
    Z = zlib:open(),
    zlib:inflateInit(Z),
    % This is so annoying
    {'EXIT',{{need_dictionary, _DictionaryAdler32},_}} = (catch zlib:inflate(Z, Compressed)),
    ok = zlib:inflateSetDictionary(Z, Dictionary),
    Uncompressed = zlib:inflate(Z, Compressed),
    ?ASSERT((is_binary(Uncompressed) orelse is_list(Uncompressed)),
            insuficcient_data_for_decompression),
    zlib:close(Z),
    Uncompressed.

-spec coalesce(Value :: term(), Default :: term()) -> term().
coalesce(undefined, Default) -> Default;
coalesce(Value, _Default) -> Value.

binary_to_hex(Value) ->
    integer_to_list(binary:decode_unsigned(iolist_to_binary(Value), big), 16).

filtermapfoldl(FilterMapFoldFun, Acc0, List) ->
    {RevFilterMapped, AccN} =
        lists:foldl(
          fun (Value, {RevFilterMappedAcc, Acc}) ->
                  {FilterMapResult, NewAcc} = FilterMapFoldFun(Value, Acc),
                  NewRevFilterMappedAcc =
                    case FilterMapResult of
                        false -> RevFilterMappedAcc;
                        true -> [Value | RevFilterMappedAcc];
                        {true, MappedValue} -> [MappedValue | RevFilterMappedAcc]
                    end,
                  {NewRevFilterMappedAcc, NewAcc}
          end,
          {[], Acc0},
          List),

    FilterMapped = lists:reverse(RevFilterMapped),
    {FilterMapped, AccN}.

now_us() ->
    os:system_time(micro_seconds).


