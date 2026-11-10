"""Dependency providers (kept separate so tests can override them cleanly)."""
from fastapi import Request


def get_store(request: Request):
    return request.app.state.store


def get_bundle(request: Request):
    return request.app.state.bundle