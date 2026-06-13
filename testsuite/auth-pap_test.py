#!/usr/bin/env python3
# PAP authentication: a server requiring PAP must let a client with the
# right secret connect, and must refuse one with the wrong secret.

from pppfns import (
    EXIT_AUTH_TOPEER_FAILED, EXIT_PEER_AUTH_FAILED,
    PppPair, require_link_env, test_fail,
)

require_link_env()

SECRETS_OK = 'cli\tsrv\t"s3cret"\t*\n'
SECRETS_BAD = 'cli\tsrv\t"wrong"\t*\n'

# b is the server (requires PAP), a is the client.
server_kwargs = dict(noauth=False, pap_secrets=SECRETS_OK)
server_options = ['auth', 'require-pap', 'name', 'srv']
client_options = ['user', 'cli', 'remotename', 'srv']

print('PAP with correct secret:')
with PppPair(a_options=client_options, b_options=server_options,
             a_kwargs=dict(pap_secrets=SECRETS_OK), b_kwargs=server_kwargs,
             name='good') as pair:
    pair.up()
    if 'Peer cli authenticated with PAP' not in pair.b.log_text():
        test_fail('server log lacks "Peer cli authenticated with PAP"')
    pair.down()

print('PAP with wrong secret:')
with PppPair(a_options=client_options, b_options=server_options,
             a_kwargs=dict(pap_secrets=SECRETS_BAD), b_kwargs=server_kwargs,
             name='bad') as pair:
    pair.start()
    pair.b.wait_for_text('PAP peer authentication failed for cli')
    pair.a.expect_exit({EXIT_AUTH_TOPEER_FAILED, EXIT_PEER_AUTH_FAILED})
    if 'remote IP address' in pair.a.log_text():
        test_fail('link came up despite failed PAP authentication')
