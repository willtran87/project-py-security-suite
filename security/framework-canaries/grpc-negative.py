"""Negative detection canary for the governed gRPC transport model."""

import grpc


def open_authenticated_channel(endpoint: str, roots: bytes):
    credentials = grpc.ssl_channel_credentials(root_certificates=roots)
    return grpc.secure_channel(endpoint, credentials)
