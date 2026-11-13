#!/usr/bin/env python3
# "mppe permitted": pppd doesn't ask for MPPE and sends no CCP request of
# its own until the peer has sent one. When the peer asks for MPPE, pppd
# asks for it too and goes on as with "mppe preferred"; otherwise the link
# comes up as with MPPE disabled. Bad values are option errors.

import os
import re
import socket
import subprocess

from pppfns import (
    EXIT_HANGUP, EXIT_NEGOTIATION_FAILED, EXIT_OK, EXIT_OPTION_ERROR, IP_A,
    IP_B, IS_LINUX, PPPD, PPPD_PEER,
    PppPair, PppPeer, require_link_env, sudo_prefix, test_fail, test_skipped,
)

require_link_env()

for binary in {PPPD, PPPD_PEER}:
    with open(binary, 'rb') as f:
        if b'Peer asked for MPPE' not in f.read():
            test_skipped(f'{binary} has no mppe permitted')
if IS_LINUX:
    subprocess.run(sudo_prefix() + ['modprobe', 'ppp_mppe'],
                   capture_output=True)
    if not os.path.exists('/sys/module/ppp_mppe'):
        test_skipped('no kernel MPPE support (ppp_mppe)')

# MPPE keys come from MS-CHAP, so b authenticates a with MS-CHAPv2.
server_kwargs = dict(noauth=False, chap_secrets='cli\tsrv\t"s3cret"\t*\n')
server_options = ['auth', 'require-mschap-v2', 'name', 'srv']
client_options = ['user', 'cli', 'remotename', 'srv', 'password', 's3cret']
pap_options = ['auth', 'require-pap', 'name', 'srv']
pap_kwargs = dict(noauth=False, pap_secrets='cli\tsrv\t"s3cret"\t*\n')

CCP_UP = r'\S.* compression enabled'
NO_MPPE = r'MPPE (preferred|permitted) but not negotiated'
ASKED = 'Peer asked for MPPE, asking for it too'


def pair(name, a_mppe, b_mppe, server_opts=None, kwargs=None):
    return PppPair(a_options=client_options + a_mppe,
                   b_options=(server_opts or server_options) + b_mppe,
                   b_kwargs=kwargs or server_kwargs, name=name)


def show(a_mppe, b_mppe):
    print(f'{" ".join(a_mppe) or "(none)"} vs {" ".join(b_mppe) or "(none)"}:')


def check_common(peer):
    log = peer.log_text()
    if len(re.findall(r'local +IP address', log)) != 1:
        test_fail(f'pppd {peer.name}: IPCP did not come up once')
    if 'one direction only' in log:
        test_fail(f'pppd {peer.name}: MPPE in one direction only')


def check_waits(peer):
    # The permitted side sends its first CCP request only after the
    # peer's, and that request already has MPPE in it.
    log = peer.log_text()
    rcvd = log.find('rcvd [CCP ConfReq')
    sent = re.search(r'sent \[CCP ConfReq[^\]]*\]', log)
    if rcvd < 0 or sent is None or sent.start() < rcvd:
        test_fail(f'pppd {peer.name}: sent a CCP request before the peer')
    if '<mppe' not in sent.group(0):
        test_fail(f'pppd {peer.name}: first CCP request without MPPE: '
                  f'{sent.group(0)}')
    if ASKED not in log:
        test_fail(f'pppd {peer.name}: no "{ASKED}"')


def mppe(name, a_mppe, b_mppe, expect, permitted):
    show(a_mppe, b_mppe)
    with pair(name, a_mppe, b_mppe) as p:
        p.up()
        for peer in (p.a, p.b):
            got = peer.wait_for_text(CCP_UP).group(0)
            print(f'  {peer.name}: {got}')
            if got != f'MPPE {expect} stateless compression enabled':
                test_fail(f'pppd {peer.name}: expected MPPE {expect}, '
                          f'got "{got}"')
            if re.search(NO_MPPE, peer.log_text()):
                test_fail(f'pppd {peer.name}: gave up MPPE but it came up')
        got = p.a.ping(IP_B)
        print(f'  {got}/3 pings')
        if got != 3:
            test_fail(f'pppd a: {got}/3 pings over the MPPE link')
        for peer in (p.a, p.b):
            check_common(peer)
            if peer.name.endswith(permitted):
                check_waits(peer)


def no_ccp(name, a_mppe, b_mppe, warns=None, server_opts=None, kwargs=None):
    show(a_mppe, b_mppe)
    with pair(name, a_mppe, b_mppe, server_opts, kwargs) as p:
        p.up()
        # The pings give CCP time to finish before the logs are read.
        got = p.a.ping(IP_B)
        for peer in (p.a, p.b):
            log = peer.log_text()
            if 'sent [CCP' in log:
                test_fail(f'pppd {peer.name}: sent a CCP packet')
            if re.search(CCP_UP, log):
                test_fail(f'pppd {peer.name}: compression came up')
            warned = re.search(NO_MPPE, log) is not None
            if warned != (warns is not None and peer.name.endswith(warns)):
                test_fail(f'pppd {peer.name}: expected the warning only '
                          f'on {warns}')
            check_common(peer)
        print(f'  no CCP, warning on {warns}, {got}/3 pings')
        if got != 3:
            test_fail(f'pppd a: {got}/3 pings over the unencrypted link')


def deflate(name, a_mppe, b_mppe):
    show(a_mppe, b_mppe)
    with pair(name, a_mppe, b_mppe) as p:
        p.up()
        for peer in (p.a, p.b):
            got = peer.wait_for_text(CCP_UP).group(0)
            print(f'  {peer.name}: {got}')
            if not got.startswith('Deflate'):
                test_fail(f'pppd {peer.name}: expected Deflate, got "{got}"')
        for peer in (p.a, p.b):
            log = peer.log_text()
            if re.search(NO_MPPE, log) or ASKED in log:
                test_fail(f'pppd {peer.name}: MPPE was asked for')
            check_common(peer)


def closed(name, a_mppe, b_mppe, who, text):
    show(a_mppe, b_mppe)
    with pair(name, a_mppe, b_mppe) as p:
        p.start()
        peer = p.a if who == 'a' else p.b
        got = peer.wait_for_text(text).group(0)
        print(f'  {peer.name}: {got}')
        # The side that gives up closes; the other sees the link hang up.
        closer = peer
        for peer in (p.a, p.b):
            code = peer.expect_exit({EXIT_NEGOTIATION_FAILED if peer is closer
                                     else EXIT_HANGUP})
            print(f'  {peer.name}: exit {code}')
            log = peer.log_text()
            if 'remote IP address' in log:
                test_fail(f'pppd {peer.name}: IPCP came up')
            if ASKED in log:
                test_fail(f'pppd {peer.name}: asked for MPPE')


def parse(name, args, code, text=None):
    print(f'mppe {" ".join(args)}:')
    sock, other = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    peer = PppPeer(name, PPPD, IP_A, IP_B, options=['mppe'] + args + ['dryrun'])
    peer.start(sock)
    sock.close()
    got = peer.expect_exit({code}, timeout=20)
    other.close()
    if text is not None and text not in peer.log_text():
        test_fail(f'mppe {" ".join(args)}: no "{text}" in the dryrun output')
    print(f'  exit {got}')


PERM = ['mppe', 'permitted']

mppe('perm-req', PERM, ['require-mppe'], '128-bit', 'a')
mppe('req-perm', ['require-mppe'], PERM, '128-bit', 'b')
mppe('perm-pref', PERM, ['mppe', 'preferred'], '128-bit', 'a')
mppe('pref-perm', ['mppe', 'preferred'], PERM, '128-bit', 'b')
mppe('perm40-req', ['mppe', 'permitted,40'], ['require-mppe'], '40-bit', 'a')

no_ccp('perm-perm', PERM, PERM)
no_ccp('perm-noccp', PERM, ['noccp'])
no_ccp('perm-pap-pref', PERM, ['mppe', 'preferred'], 'b',
       server_opts=pap_options, kwargs=pap_kwargs)

deflate('perm-none', PERM, [])
deflate('none-perm', [], PERM)
deflate('req-then-perm', ['require-mppe'] + PERM, [])
deflate('perm-then-nomppe', PERM + ['nomppe'], PERM)

closed('perm128-req40', ['mppe', 'permitted,128'], ['require-mppe-40'],
       'b', 'MPPE required but peer (refused|negotiation failed)')
closed('perm-then-req', PERM + ['require-mppe'], [],
       'a', 'MPPE required but peer (refused|negotiation failed)')

parse('dump', ['permitted'], EXIT_OK, 'mppe permitted,40,128')
parse('dump128', ['permitted,128'], EXIT_OK, 'mppe permitted,128')
for bad in ('permit', 'permitted,', 'permitted,56', 'permittedx'):
    parse('bad-' + bad.replace(',', '-'), [bad], EXIT_OPTION_ERROR)
