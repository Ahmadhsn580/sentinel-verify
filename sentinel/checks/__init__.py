"""Check package. Importing base triggers registration of every module."""

from .base import REGISTRY, Check, all_checks, register

__all__ = ["REGISTRY", "Check", "all_checks", "register"]
