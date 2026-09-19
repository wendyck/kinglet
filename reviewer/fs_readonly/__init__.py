"""Jailed read-only filesystem access for the Kinglet reviewer (SPEC.md §5.4).

This is the only tool surface the reviewer agent has. Everything the model can
see about a PR arrives through here, and nothing it does can leave here.
"""

__all__ = ["server"]
