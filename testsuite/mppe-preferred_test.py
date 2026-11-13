#!/usr/bin/env python3
# "mppe preferred": pppd uses MPPE when the peer agrees, and otherwise
# brings the link up without it, without other compression and with a
# warning, in either role. A peer that requires MPPE still gets MPPE or a
# closed link, and a later require-mppe makes MPPE required again. Bad mppe
# values are option errors.

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
        if b'for mppe option' not in f.read():
            test_skipped(f'{binary} has no mppe option')
if IS_LINUX:
    subprocess.run(sudo_prefix() + ['modprobe', 'ppp_mppe'],
                   capture_output=True)
    if not os.path.exists('/sys/module/ppp_mppe'):
        test_skipped('no kernel MPPE support (ppp_mppe)')

# MPPE keys come from MS-CHAP, so b authenticates a with MS-CHAPv2.
server_kwargs = dict(noauth=False, chap_secrets='cli\tsrv\t"s3cret"\t*\n')
server_options = ['auth', 'require-mschap-v2', 'name', 'srv']
client_options = ['user', 'cli', 'remotename', 'srv', 'password', 's3cret']

CCP_UP = r'\S.* compression enabled'
NO_MPPE = 'MPPE preferred but not negotiated, data is sent unencrypted'


def pair(name, a_mppe, b_mppe, server_opts=None, kwargs=None):
    return PppPair(a_options=client_options + a_mppe,
                   b_options=(server_opts or server_options) + b_mppe,
                   b_kwargs=kwargs or server_kwargs, name=name)


def mppe(name, a_mppe, b_mppe, expect):
    print(f'{" ".join(a_mppe)} vs {" ".join(b_mppe)}:')
    with pair(name, a_mppe, b_mppe) as p:
        p.up()
        for peer in (p.a, p.b):
            got = peer.wait_for_text(CCP_UP).group(0)
            print(f'  {peer.name}: {got}')
            if got != f'MPPE {expect} stateless compression enabled':
                test_fail(f'pppd {peer.name}: expected MPPE {expect}, '
                          f'got "{got}"')
            if NO_MPPE in peer.log_text():
                test_fail(f'pppd {peer.name}: gave up MPPE but it came up')
        got = p.a.ping(IP_B)
        print(f'  {got}/3 pings')
        if got != 3:
            test_fail(f'pppd a: {got}/3 pings over the MPPE link')


def plain(name, a_mppe, b_mppe, warns, server_opts=None, kwargs=None):
    print(f'{" ".join(a_mppe)} vs {" ".join(b_mppe)}:')
    with pair(name, a_mppe, b_mppe, server_opts, kwargs) as p:
        p.up()
        # The pings give CCP time to finish before the logs are read.
        got = p.a.ping(IP_B)
        for peer in (p.a, p.b):
            log = peer.log_text()
            if re.search(CCP_UP, log):
                test_fail(f'pppd {peer.name}: compression came up')
            if (NO_MPPE in log) != (peer.name.endswith(warns)):
                test_fail(f'pppd {peer.name}: expected the warning only '
                          f'on {warns}')
            if len(re.findall(r'local +IP address', log)) != 1:
                test_fail(f'pppd {peer.name}: IPCP did not come up once')
        print(f'  up without MPPE, warning on {warns}, {got}/3 pings')
        if got != 3:
            test_fail(f'pppd a: {got}/3 pings over the unencrypted link')


def deflate(name, a_mppe, b_mppe):
    print(f'{" ".join(a_mppe)} vs {" ".join(b_mppe)}:')
    with pair(name, a_mppe, b_mppe) as p:
        p.up()
        for peer in (p.a, p.b):
            got = peer.wait_for_text(CCP_UP).group(0)
            print(f'  {peer.name}: {got}')
            if not got.startswith('Deflate'):
                test_fail(f'pppd {peer.name}: expected Deflate, got "{got}"')
            if NO_MPPE in peer.log_text():
                test_fail(f'pppd {peer.name}: warned about MPPE')


def closed(name, a_mppe, b_mppe, who, text):
    print(f'{" ".join(a_mppe)} vs {" ".join(b_mppe)}:')
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
            if 'remote IP address' in peer.log_text():
                test_fail(f'pppd {peer.name}: IPCP came up')


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


mppe('pref-req', ['mppe', 'preferred'], ['require-mppe'], '128-bit')
mppe('req-pref', ['require-mppe'], ['mppe', 'preferred'], '128-bit')
mppe('pref-pref', ['mppe', 'preferred'], ['mppe', 'preferred'], '128-bit')
mppe('pref40', ['mppe', 'preferred,40'], ['require-mppe'], '40-bit')

plain('pref-none', ['mppe', 'preferred'], [], 'a')
plain('none-pref', [], ['mppe', 'preferred'], 'b')
plain('pref-noccp', ['mppe', 'preferred'], ['noccp'], 'a')
plain('pref-pap', ['mppe', 'preferred'], [], 'a',
      server_opts=['auth', 'require-pap', 'name', 'srv'],
      kwargs=dict(noauth=False, pap_secrets='cli\tsrv\t"s3cret"\t*\n'))
plain('pap-pref', [], ['mppe', 'preferred'], 'b',
      server_opts=['auth', 'require-pap', 'name', 'srv'],
      kwargs=dict(noauth=False, pap_secrets='cli\tsrv\t"s3cret"\t*\n'))
plain('pref128-no128', ['mppe', 'preferred,128', 'nomppe-128'], [], 'a')
plain('req-then-pref', ['require-mppe', 'mppe', 'preferred'], [], 'a')

deflate('pref-then-nomppe', ['mppe', 'preferred', 'nomppe'], [])

closed('pref40-req128', ['mppe', 'preferred,40'], ['require-mppe-128'],
       'b', 'MPPE required but peer (refused|negotiation failed)')
closed('pref-then-req', ['mppe', 'preferred', 'require-mppe'], [],
       'a', 'MPPE required but peer (refused|negotiation failed)')

parse('dump', ['preferred'], EXIT_OK, 'mppe preferred,40,128')
parse('dump128', ['required,128'], EXIT_OK, 'mppe required,128')
for bad in ('bogus', 'optional', 'preferred,56', 'preferred,', 'disabled,40'):
    parse('bad-' + bad.replace(',', '-'), [bad], EXIT_OPTION_ERROR)
