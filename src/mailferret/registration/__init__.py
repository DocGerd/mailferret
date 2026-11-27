"""Client-config registration core; see ARCHITECTURE A§9.5-9.6, SECURITY T-12."""

from mailferret.registration.discovery import (
    Candidate,
    claude_code_scope_file,
    desktop_candidates,
)
from mailferret.registration.files import (
    ConcurrentModificationError,
    DuplicateEntryError,
    EntryState,
    RegistrationError,
    atomic_write_text,
    backup_file,
    entry_state,
    merge_server,
)

__all__ = [
    "Candidate",
    "ConcurrentModificationError",
    "DuplicateEntryError",
    "EntryState",
    "RegistrationError",
    "atomic_write_text",
    "backup_file",
    "claude_code_scope_file",
    "desktop_candidates",
    "entry_state",
    "merge_server",
]
