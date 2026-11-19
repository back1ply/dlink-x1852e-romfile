"""Live-device helpers for the DSL-X1852E: talk to a unit on your LAN.

These are first-class ``romfile`` subcommands (``fetch``, ``acl``, ``telnet``,
``recv``, ``tftp``) but deliberately isolated in this subpackage: the top-level
package stays pure, deterministic and offline (file format + firmware), while
anything that opens a socket lives here. Everything is standard library only.

Credentials never live in source -- see :mod:`dlink_romfile.device.secrets`.
"""


class DeviceError(Exception):
    """An expected device-interaction failure (login refused, timeout, bad reply).

    The CLI turns this into a one-line stderr message and a non-zero exit, with no
    traceback.
    """
