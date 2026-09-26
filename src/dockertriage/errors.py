"""Exception types.

These live apart from the registry client because batch mode catches
RateLimited without importing anything that opens a socket.
"""


class RateLimited(RuntimeError):
    """The registry refused us for volume, not for permissions."""


class RetryableError(Exception):
    """An error worth another attempt, e.g. a dropped keep-alive socket."""
