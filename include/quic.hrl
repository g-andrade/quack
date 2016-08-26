-ifndef(QUIC_HRL).
-define(QUIC_HRL, included).

-define(ASSERT(Condition, FailureException), (((Condition)) orelse exit(FailureException))).
-define(QUIC_VERSION, <<"Q034">>).

-endif.
