#!/usr/bin/env python3
# CHAP authentication: a server requiring CHAP must let a client with the
# right secret connect, and must refuse one with the wrong secret.

from pppfns import (
    EXIT_AUTH_TOPEER_FAILED, EXIT_PEER_AUTH_FAILED,
    PppPair, require_link_env, test_fail,
)

require_link_env()

SECRETS_OK = 'cli\tsrv\t"s3cret"\t*\n'
SECRETS_BAD = 'cli\tsrv\t"wrong"\t*\n'

# b is the server (requires CHAP), a is the client.
server_kwargs = dict(noauth=False, chap_secrets=SECRETS_OK)
server_options = ['auth', 'require-chap', 'name', 'srv']
client_options = ['user', 'cli', 'remotename', 'srv']

print('CHAP with correct secret:')
with PppPair(a_options=client_options, b_options=server_options,
             a_kwargs=dict(chap_secrets=SECRETS_OK), b_kwargs=server_kwargs,
             name='good') as pair:
    pair.up()
    if 'Peer cli authenticated with CHAP' not in pair.b.log_text():
        test_fail('server log lacks "Peer cli authenticated with CHAP"')
    pair.down()

print('CHAP with wrong secret:')
with PppPair(a_options=client_options, b_options=server_options,
             a_kwargs=dict(chap_secrets=SECRETS_BAD), b_kwargs=server_kwargs,
             name='bad') as pair:
    pair.start()
    # The server must reject the client; both sides then exit on their own.
    pair.b.wait_for_text('Peer cli failed CHAP authentication')
    pair.a.expect_exit({EXIT_AUTH_TOPEER_FAILED, EXIT_PEER_AUTH_FAILED})
    if 'remote IP address' in pair.a.log_text():
        test_fail('link came up despite failed CHAP authentication')
