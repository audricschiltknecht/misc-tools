#!/usr/bin/env python3

# Simple script to try and fetch a missing TLS certificate
# By default, it will try to find the root CA used to sign a site's certificate.
#
# Note: Not sure how well it will work for certs that are cross-signed
#
import socket
import sys

import certifi
import click
import OpenSSL

START_LINE = "-----BEGIN CERTIFICATE-----"


def load_ca():
    """
    Load the list of CA from certifi and convert them to X509 objects.
    """
    result = []
    cert_slots = certifi.contents().split(START_LINE)
    for single_pem_cert in cert_slots[1:]:
        pem_content = START_LINE + single_pem_cert
        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, pem_content.encode()
        )
        result.append(cert)
    return result


def find_cert(hostname, port, depth):
    """
    Open a connection to `hostname`:`port` and find the `depth` certificate used
    in the certificate chain.

    If `depth` is -1, then find the root CA.
    """
    ca_list = load_ca()

    context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_CLIENT_METHOD)
    context.load_verify_locations(cafile=certifi.where())

    conn = OpenSSL.SSL.Connection(
        context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    )
    conn.settimeout(5)
    conn.connect((hostname, port))
    conn.setblocking(1)
    conn.set_tlsext_host_name(hostname.encode())
    conn.do_handshake()

    cert_chain = conn.get_peer_cert_chain()
    if depth > len(cert_chain):
        depth = -1

    last_cert = cert_chain[depth]
    if depth != -1:
        # We want a cert that is present in the chain, return it
        return last_cert

    # We are looking for a root ca from the system's CA store
    cn = last_cert.get_issuer().get_components()
    for ca_cert in ca_list:
        if ca_cert.get_subject().get_components() == cn:
            return ca_cert

    return None


@click.command()
@click.option("-n", "--hostname", required=True, help="Hostname of the remote server.")
@click.option("-p", "--port", default=443, help="Port to connect to")
@click.option("-d", "--depth", default=-1, help="Depth of certificate to retrieve")
def main(hostname, port=443, depth=-1):
    try:
        ca = find_cert(hostname, port, depth)
        if ca is not None:
            pem = OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, ca
            ).decode()
            print(pem)
            print("Found certificate!", file=sys.stderr)
        else:
            print("Cannot find certificate in local store", file=sys.stderr)
    except Exception as e:
        print(f"Cannot connect to server: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
