"""Shared exceptions for the loopback HTTP layer."""
from __future__ import annotations


class AppError(Exception):
    def __init__(self, code, message, status=400):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)
