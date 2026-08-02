# SPDX-License-Identifier: Apache-2.0
"""Minimal, dependency-free Python client for the decern PDP (AuthZEN 1.0)."""

from .client import Client, Decision, DecernError

__all__ = ["Client", "Decision", "DecernError"]
__version__ = "0.1.0"
