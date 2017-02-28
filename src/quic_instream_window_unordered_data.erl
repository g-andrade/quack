-module(quic_instream_window_unordered_data).
-behaviour(quic_instream_window).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([new/0]).

%% ------------------------------------------------------------------
%% quic_instream_window Function Exports
%% ------------------------------------------------------------------

-export([new_cb/1]).
-export([insert_cb/3]).
-export([consume_cb/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(DEFAULT_CAPACITY, (8 * 1024)).

%% ------------------------------------------------------------------
%% Record Definitions
%% ------------------------------------------------------------------

-record(contiguous, {
          offset :: non_neg_integer(),
          capacity :: non_neg_integer(),
          size :: non_neg_integer(),
          data :: iodata()
         }).
-opaque contiguous() :: #contiguous{}.
-export_type([contiguous/0]).

-record(fragmented, {
          offset :: non_neg_integer(),
          capacity :: non_neg_integer(),
          split_offset :: non_neg_integer(),
          split_left :: value(),
          split_left_size :: non_neg_integer(),
          split_right :: value(),
          split_right_size :: non_neg_integer()
         }).
-opaque fragmented() :: #fragmented{}.
-export_type([fragmented/0]).

%% ------------------------------------------------------------------
%% Type Definitions
%% ------------------------------------------------------------------

-opaque value() :: contiguous() | fragmented().
-export_type([value/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec new() -> quic_instream_window:value().
new() ->
    quic_instream_window:new(?MODULE, [?DEFAULT_CAPACITY]).

%% ------------------------------------------------------------------
%% quic_instream_window Function Definitions
%% ------------------------------------------------------------------

-spec new_cb([Capacity :: non_neg_integer()]) -> contiguous().
new_cb([Capacity]) ->
    #contiguous{ offset = 0,
                 capacity = Capacity,
                 size = 0,
                 data = "" }.

-spec insert_cb(Window :: value(), ChunkOffset :: non_neg_integer(), Chunk :: iodata())
        -> {ok, NewWindow :: value()} | {error, stale_data | overlapping_data | window_full}.
insert_cb(Window, ChunkOffset, Chunk) ->
    ChunkSize = iolist_size(Chunk),
    insert(Window, ChunkOffset, ChunkSize, Chunk, right).

-spec consume_cb(Window :: value()) -> {NewWindow :: value(),
                                        {DataSize :: non_neg_integer(),
                                         Data :: iodata()}}.
consume_cb(Window) ->
    {NewWindow, DataSize, Data} = consume_without_expansion(Window),
    ExpandedWindow = expand(NewWindow, DataSize),
    {ExpandedWindow, {DataSize, Data}}.

%% ------------------------------------------------------------------
%% Contiguous
%% ------------------------------------------------------------------

-spec insert_contiguous(contiguous(), non_neg_integer(), non_neg_integer(),
                        non_neg_integer(), iodata(), left | right)
        -> {ok, value()} | {error, stale_data | overlapping_data | window_full}.
insert_contiguous(_Contiguous, DataEndOffset, ChunkOffset, _ChunkSize, _Chunk, _Area)
  when ChunkOffset < DataEndOffset->
    {error, stale_data};
insert_contiguous(Contiguous, _DataEndOffset, ChunkOffset, ChunkSize, _Chunk, Area)
  when ((ChunkOffset - Contiguous#contiguous.offset)  + ChunkSize)
       > Contiguous#contiguous.capacity ->
    case Area of
        right -> {error, window_full};
        left -> {error, overlapping_data}
    end;
insert_contiguous(Contiguous, DataEndOffset, ChunkOffset, ChunkSize, Chunk, _Area)
  when ChunkOffset =:= DataEndOffset ->
     NewContiguous =
        Contiguous#contiguous{
          size = Contiguous#contiguous.size + ChunkSize,
          data = [Contiguous#contiguous.data, Chunk] % @todo flatten iolist after a certain limit?
         },
    {ok, NewContiguous};
insert_contiguous(Contiguous, DataEndOffset, ChunkOffset, ChunkSize, Chunk, _Area)
  when ChunkOffset > DataEndOffset ->
    #contiguous{ offset = Offset,
                 capacity = Capacity,
                 size = Size,
                 data = Data } = Contiguous,
    SplitLeft =
        #contiguous{
           capacity = ChunkOffset - Offset,
           offset = Offset,
           size = Size,
           data = Data },
    SplitRight =
        #contiguous{
           capacity = (Offset + Capacity) - ChunkOffset,
           offset = Offset + SplitLeft#contiguous.capacity,
           size = ChunkSize,
           data = Chunk },
    Fragmented =
        #fragmented{
           offset = Offset,
           capacity = Capacity,
           split_offset = ChunkOffset,
           split_left = SplitLeft,
           split_left_size = Size,
           split_right = SplitRight,
           split_right_size = ChunkSize },
    {ok, Fragmented}.

-spec consume_contiguous(contiguous()) -> {contiguous(), non_neg_integer(), iodata()}.
consume_contiguous(Contiguous) ->
    #contiguous{ capacity = Capacity,
                 offset = Offset,
                 size = Size,
                 data = Data } = Contiguous,

    NewContiguous =
        Contiguous#contiguous{
          capacity = Capacity - Size,
          offset = Offset + Size,
          size = 0,
          data = "" },
    {NewContiguous, Size, Data}.

%% ------------------------------------------------------------------
%% Fragmented
%% ------------------------------------------------------------------

-spec insert_fragmented(fragmented(), non_neg_integer(), non_neg_integer(),
                        iodata(), left | right)
        -> {ok, fragmented()} | {error, stale_data | overlapping_data | window_full}.
insert_fragmented(Fragmented, ChunkOffset, ChunkSize, Chunk, Area) ->
    {SplitIndex, SplitSizeIndex, SplitArea} =
        case ChunkOffset < Fragmented#fragmented.split_offset of
            true -> {#fragmented.split_left, #fragmented.split_left_size, left};
            false -> {#fragmented.split_right, #fragmented.split_right_size, Area}
        end,

    Split = element(SplitIndex, Fragmented),
    case insert(Split, ChunkOffset, ChunkSize, Chunk, SplitArea) of
        {ok, NewSplit} ->
            NewFragmented =
                setelement(SplitSizeIndex,
                           setelement(SplitIndex, Fragmented, NewSplit),
                           window_size(NewSplit)),
            {ok, NewFragmented};
        {error, _} = Error ->
            Error
    end.

-spec consume_fragmented(fragmented()) -> {value(), non_neg_integer(), iodata()}.
consume_fragmented(#fragmented{ offset = Offset,
                                split_left_size = SplitLeftSize,
                                split_offset = SplitOffset } = Fragmented)
  when (Offset + SplitLeftSize) < SplitOffset ->
    % this means we can't fully consume left size,
    % and therefore we can't then proceed to right either
    #fragmented{ capacity = Capacity,
                 split_left = SplitLeft } = Fragmented,
    {NewSplitLeft, DataSize, Data} = consume_without_expansion(SplitLeft),
    true = (DataSize =< SplitLeftSize),
    NewFragmented =
        Fragmented#fragmented{
          capacity = Capacity - DataSize,
          offset = Offset + DataSize,
          split_left = NewSplitLeft,
          split_left_size = SplitLeftSize - DataSize
         },
    {NewFragmented, DataSize, Data};
consume_fragmented(#fragmented{ offset = Offset,
                                split_left_size = SplitLeftSize,
                                split_offset = SplitOffset } = Fragmented)
  when (Offset + SplitLeftSize) =:= SplitOffset ->
    % this means we can fully consume left size
    #fragmented{ split_left = SplitLeft,
                 split_right = SplitRight } = Fragmented,
    {_NewSplitLeft, LeftDataSize, LeftData} = consume_without_expansion(SplitLeft),
    LeftDataSize = SplitLeftSize,
    {NewSplitRight, RightDataSize, RightData} = consume_without_expansion(SplitRight),
    % throw away both left split and this frag
    Data = [LeftData, RightData],
    DataSize = LeftDataSize + RightDataSize,
    {NewSplitRight, DataSize, Data}.

%% ------------------------------------------------------------------
%% Common
%% ------------------------------------------------------------------

-spec window_size(value()) -> non_neg_integer().
window_size(#contiguous{ size = Size }) ->
    Size;
window_size(#fragmented{ split_left_size = SplitLeftSize,
                         split_right_size = SplitRightSize }) ->
    SplitLeftSize + SplitRightSize.

-spec insert(Window :: value(), ChunkOffset :: non_neg_integer(),
             ChunkSize :: non_neg_integer(), Chunk :: iodata(),
             Area :: left | right)
        -> {ok, NewWindow :: value()} | {error, stale_data | overlapping_data | window_full}.
insert(#contiguous{} = Contiguous, ChunkOffset, ChunkSize, Chunk, Area) ->
    DataEndOffset = Contiguous#contiguous.offset + Contiguous#contiguous.size,
    insert_contiguous(Contiguous, DataEndOffset, ChunkOffset, ChunkSize, Chunk, Area);
insert(#fragmented{} = Fragmented, ChunkOffset, ChunkSize, Chunk, Area) ->
    insert_fragmented(Fragmented, ChunkOffset, ChunkSize, Chunk, Area).

-spec consume_without_expansion(value()) -> {value(), non_neg_integer(), iodata()}.
consume_without_expansion(#contiguous{} = Contiguous) ->
    consume_contiguous(Contiguous);
consume_without_expansion(#fragmented{} = Fragmented) ->
    consume_fragmented(Fragmented).

-spec expand(value(), non_neg_integer()) -> value().
expand(Contiguous, Increment) when Increment < 1 ->
    Contiguous;
expand(Contiguous, Increment)
  when is_record(Contiguous, contiguous) ->
    Capacity = Contiguous#contiguous.capacity,
    Contiguous#contiguous{ capacity = Capacity + Increment };
expand(Fragmented, Increment)
  when is_record(Fragmented, fragmented) ->
    #fragmented{ capacity = Capacity,
                 split_right = SplitRight } = Fragmented,
    Capacity = Fragmented#fragmented.capacity,
    Fragmented#fragmented{
      capacity = Capacity + Increment,
      split_right = expand(SplitRight, Increment) }.
