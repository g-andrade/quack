-module(quic_proto_f16).

-include("quic.hrl").

%% @see: https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit#

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([decode/1]).
-export([encode/1]).

%% ------------------------------------------------------------------
%% Macro definitions
%% ------------------------------------------------------------------

-define(EXPONENT_BITSIZE, 5).
-define(MANTISSA_BITSIZE, 11).

-define(MAX_EXPONENT_VALUE, ((1 bsl ?EXPONENT_BITSIZE) - 1)).
-define(MAX_MANTISSA_VALUE, ((1 bsl ?MANTISSA_BITSIZE) - 1)).

-define(MAX_VALUE, ((?MAX_MANTISSA_VALUE bor (1 bsl ?MANTISSA_BITSIZE)) bsl (?MAX_EXPONENT_VALUE - 1))).

%% ------------------------------------------------------------------
%% Type definitions
%% ------------------------------------------------------------------

-type exponent() :: 0..?MAX_EXPONENT_VALUE.
-type mantissa() :: 0..?MAX_MANTISSA_VALUE.

-type value() :: 0..?MAX_VALUE. % err, more or less. not specifying the gaps
-export_type([value/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec decode(binary()) -> non_neg_integer().
decode(<<EncodedExponent:?EXPONENT_BITSIZE, EncodedMantissa:?MANTISSA_BITSIZE>>) ->
    decode(EncodedExponent, EncodedMantissa).

-spec encode(non_neg_integer()) -> binary().
encode(Value) when Value >= 0 ->
    encode(0, Value).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec decode(exponent(), mantissa()) -> integer().
decode(0, EncodedMantissa) ->
    EncodedMantissa;
decode(EncodedExponent, EncodedMantissa) ->
    Mantissa = EncodedMantissa bor (1 bsl ?MANTISSA_BITSIZE),
    Exponent = EncodedExponent - 1,
    Mantissa bsl Exponent.

-spec encode(Exponent :: non_neg_integer(), Mantissa :: non_neg_integer()) -> binary().
encode(Exponent, Mantissa) when Exponent =:= 0, Mantissa =< ?MAX_MANTISSA_VALUE ->
    <<Exponent:?EXPONENT_BITSIZE, Mantissa:?MANTISSA_BITSIZE>>;
encode(Exponent, Mantissa) when Exponent < ?MAX_EXPONENT_VALUE, (Mantissa > (?MAX_MANTISSA_VALUE bsl (Exponent + 1))) ->
    encode(Exponent + 1, Mantissa);
encode(Exponent, _Mantissa) when Exponent >= ?MAX_EXPONENT_VALUE ->
    <<?MAX_EXPONENT_VALUE:?EXPONENT_BITSIZE, ?MAX_MANTISSA_VALUE:?MANTISSA_BITSIZE>>;
encode(Exponent, Mantissa) ->
    EncodedExponent = Exponent + 1,
    EncodedMantissa = Mantissa bsr Exponent,
    <<EncodedExponent:?EXPONENT_BITSIZE, EncodedMantissa:?MANTISSA_BITSIZE>>.
