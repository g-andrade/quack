-module(quic_crypto_state_subscriber).

-callback notify_new_crypto_shadow(pid(), quic_crypto:shadow_state()) -> ok.
