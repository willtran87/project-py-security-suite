"""Positive detection canary for the governed gRPC transport model."""

import grpc


def open_untrusted_channel(endpoint: str):
    """Deliberately unsafe: the model must report this call."""
    return grpc.insecure_channel(endpoint)
