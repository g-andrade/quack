-module(quic_data_kv).

-include("quic_data_kv.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([fully_decode/1]).
-export([decode/1]).
-export([decode_tagged_values/1]).
-export([decode_tag_list/1]).
-export([encode/1]).
-export([encode_tagged_values/1]).
-export([encode_tag_list/1]).

%% ------------------------------------------------------------------
%% Type Exports
%% ------------------------------------------------------------------

-export_type([data_kv/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

fully_decode(Data) ->
    {DataKv, <<>>} = decode(Data),
    DataKv.

decode(<<PayloadTag:4/binary, Body/binary>>) ->
    case decode_tagged_values(Body) of
        incomplete -> incomplete;
        {TaggedValuesMap, RemainingData} ->
            {#data_kv{ tag = decode_tag(PayloadTag),
                       tagged_values = TaggedValuesMap },
             RemainingData}
    end;
decode(<<_/binary>>) ->
    incomplete.

decode_tagged_values(<<TaggedValuesLength:2/little-unsigned-integer-unit:8, 0:16,
                       Body/binary>>) ->
    EncodedTaggedValueEndOffsetsSize = 2 * 4 * TaggedValuesLength,
    <<EncodedTaggedValueEndOffsets:EncodedTaggedValueEndOffsetsSize/binary,
      EncodedValues/binary>> = Body,

    BaseOffset = 0,
    TaggedValueEndOffsets =
        (fun F(<<EncodedTag:4/binary, EndOffset:4/little-unsigned-integer-unit:8, Next/binary>>) ->
                 [{decode_tag(EncodedTag), EndOffset - BaseOffset} | F(Next)];
             F(<<>>) ->
                 []
         end)(EncodedTaggedValueEndOffsets),

    {_LastElementTag, LastElementEndOffset} = lists:last(TaggedValueEndOffsets),
    case LastElementEndOffset > iolist_size(EncodedValues) of
        true -> incomplete;
        false ->
            {TaggedValuesList, FinalEndOffset} =
                lists:mapfoldl(
                  fun ({Tag, EndOffset}, StartOffset) ->
                          {{Tag, binary:part(EncodedValues, StartOffset, EndOffset - StartOffset)},
                           EndOffset}
                  end,
                  0,
                  TaggedValueEndOffsets),
            {maps:from_list(TaggedValuesList),
             binary:part(EncodedValues, FinalEndOffset, byte_size(EncodedValues) - FinalEndOffset)}
    end.

-spec decode_tag_list(binary()) -> [binary(), ...].
decode_tag_list(<<EncodedTag:4/binary, Next/binary>>) ->
    [decode_tag(EncodedTag) | decode_tag_list(Next)];
decode_tag_list(<<>>) ->
    [].

encode(#data_kv{ tag = PayloadTag,
                 tagged_values = TaggedValuesMap }) ->
    [% message tag
     encode_tag(PayloadTag, 4),
     % body
     encode_tagged_values(TaggedValuesMap)].

encode_tagged_values(TaggedValuesMap) ->
    UnsortedTaggedValues = maps:to_list(TaggedValuesMap),
    TaggedValues =
        lists:sort(fun ({KeyA, _}, {KeyB, _}) ->
                           <<NumKeyA:4/little-unsigned-integer-unit:8>> = encode_tag(KeyA, 4),
                           <<NumKeyB:4/little-unsigned-integer-unit:8>> = encode_tag(KeyB, 4),
                           NumKeyA =< NumKeyB
                   end,
                   UnsortedTaggedValues),

    Values = [Value || {_Tag, Value} <- TaggedValues],
    {TaggedValueEndOffsets, _} =
        lists:mapfoldl(
          fun ({Tag, Value}, Acc) ->
                  NewAcc = Acc + iolist_size(Value),
                  {{Tag, NewAcc}, NewAcc}
          end,
          0,
          TaggedValues),

    [% number of keyvalue pairs with two-byte filler
     [quic_util:encode_uint(length(TaggedValues), 2), 0, 0],
     % tags and offsets
     [[encode_tag(Tag, 4), quic_util:encode_uint(EndOffset, 4)]
      || {Tag, EndOffset} <- TaggedValueEndOffsets],
     Values].

-spec encode_tag_list([binary(), ...]) -> [binary(), ...].
encode_tag_list(Tags) ->
    [encode_tag(Tag, 4) || Tag <- Tags].

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

decode_tag(Tag) ->
    TagStr = binary_to_list(Tag),
    list_to_binary(lists:takewhile(fun (Char) -> Char =/= 0 end, TagStr)).

encode_tag(Tag, Size) when is_binary(Tag); is_list(Tag) ->
    Filler = string:copies([0], Size - iolist_size(Tag)),
    iolist_to_binary([Tag, Filler]).
