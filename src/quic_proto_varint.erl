-module(quic_proto_varint).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([decode_u32/2]).
-export([encode_u32/1]).

-export([decode_u48/2]).
-export([encode_u48/1]).
-export([encode_u48/2]).
-export([u48s_encoding/1]).

-export([decode_u64/2]).
-export([encode_u64/1]).

%% ------------------------------------------------------------------
%% u32 Function Definitions
%% ------------------------------------------------------------------

decode_u32(Data, Encoding) when Encoding < 4->
    Size = (Encoding + 1),
    <<Value:Size/little-unsigned-integer-unit:8, RemainingData/binary>> = Data,
    {RemainingData, Value}.

encode_u32(Value) when Value =< 16#000000FF ->
    {<<Value:1/little-unsigned-integer-unit:8>>, 0};
encode_u32(Value) when Value =< 16#0000FFFF ->
    {<<Value:2/little-unsigned-integer-unit:8>>, 1};
encode_u32(Value) when Value =< 16#00FFFFFF ->
    {<<Value:3/little-unsigned-integer-unit:8>>, 2};
encode_u32(Value) when Value =< 16#FFFFFFFF ->
    {<<Value:4/little-unsigned-integer-unit:8>>, 3}.

%% ------------------------------------------------------------------
%% u48 Function Definitions
%% ------------------------------------------------------------------

decode_u48(<<Value:8, Data/binary>>,
           2#00) ->
    {Data, Value};
decode_u48(<<Value:2/little-unsigned-integer-unit:8, Data/binary>>,
           2#01) ->
    {Data, Value};
decode_u48(<<Value:4/little-unsigned-integer-unit:8, Data/binary>>,
           2#10) ->
    {Data, Value};
decode_u48(<<Value:6/little-unsigned-integer-unit:8, Data/binary>>,
           2#11) ->
    {Data, Value}.

encode_u48(Value) when Value =< 16#0000000000FF ->
    {encode_u48(Value, 2#00), 2#00};
encode_u48(Value) when Value =< 16#00000000FFFF ->
    {encode_u48(Value, 2#01), 2#01};
encode_u48(Value) when Value =< 16#0000FFFFFFFF ->
    {encode_u48(Value, 2#10), 2#10};
encode_u48(Value) when Value =< 16#FFFFFFFFFFFF ->
    {encode_u48(Value, 2#11), 2#11}.

encode_u48(Value, 2#00) when Value =< 16#0000000000FF ->
    <<Value:1/little-unsigned-integer-unit:8>>;
encode_u48(Value, 2#01) when Value =< 16#00000000FFFF ->
    <<Value:2/little-unsigned-integer-unit:8>>;
encode_u48(Value, 2#10) when Value =< 16#0000FFFFFFFF ->
    <<Value:4/little-unsigned-integer-unit:8>>;
encode_u48(Value, 2#11) when Value =< 16#FFFFFFFFFFFF ->
    <<Value:6/little-unsigned-integer-unit:8>>.

u48s_encoding([_|_] = Values) ->
    MaxValue = lists:max(Values),
    {_, Encoding} = encode_u48(MaxValue),
    Encoding.

%% ------------------------------------------------------------------
%% u64 Function Definitions
%% ------------------------------------------------------------------

% similar to u32 but favours 0bit-sized data instead of 8bit
decode_u64(Data, 0) ->
    {Data, 0};
decode_u64(Data, Encoding) when Encoding < 8 ->
    Size = (Encoding + 1),
    <<Value:Size/little-unsigned-integer-unit:8, RemainingData/binary>> = Data,
    {RemainingData, Value}.

encode_u64(Value) when Value =:= 0 ->
    {<<>>, 0};
encode_u64(Value) when Value =< 16#000000000000FFFF ->
    {<<Value:2/little-unsigned-integer-unit:8>>, 1};
encode_u64(Value) when Value =< 16#0000000000FFFFFF ->
    {<<Value:3/little-unsigned-integer-unit:8>>, 2};
encode_u64(Value) when Value =< 16#00000000FFFFFFFF ->
    {<<Value:4/little-unsigned-integer-unit:8>>, 3};
encode_u64(Value) when Value =< 16#000000FFFFFFFFFF ->
    {<<Value:5/little-unsigned-integer-unit:8>>, 4};
encode_u64(Value) when Value =< 16#0000FFFFFFFFFFFF ->
    {<<Value:6/little-unsigned-integer-unit:8>>, 5};
encode_u64(Value) when Value =< 16#00FFFFFFFFFFFFFF ->
    {<<Value:7/little-unsigned-integer-unit:8>>, 6};
encode_u64(Value) when Value =< 16#FFFFFFFFFFFFFFFF ->
    {<<Value:8/little-unsigned-integer-unit:8>>, 7}.
