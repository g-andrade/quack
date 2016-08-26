-ifndef(QUIC_DATA_KV_HRL).
-define(QUIC_DATA_KV_HRL, included).

-record(data_kv, {
          tag :: tag(),
          tagged_values :: tagged_values()
         }).
-type data_kv() :: #data_kv{}.
-type tag() :: binary().
-type tagged_values() :: #{tag() => binary()}.

-endif.
