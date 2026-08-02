"""obstat — an auditable decision record for agent tool calls.

*nihil obstat*: nothing stands in the way. The clearance is written down before
the act, not reconstructed after it.
"""

from .guard import Denied, Subject, guard, set_subject_resolver
from .policy import PolicyError
from .record import note

__all__ = ["Denied", "PolicyError", "Subject", "guard", "note", "set_subject_resolver"]
__version__ = "0.5.0"
