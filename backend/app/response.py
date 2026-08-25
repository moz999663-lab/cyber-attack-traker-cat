from dataclasses import dataclass

@dataclass(frozen=True)
class ResponsePlan:
    action: str
    dry_run: bool
    requires_approval: bool
    reason: str

ALLOWED_ACTIONS = {"isolate_host", "quarantine_artifact", "disable_collection"}

def plan(action: str, reason: str, dry_run: bool = True) -> ResponsePlan:
    if action not in ALLOWED_ACTIONS:
        raise ValueError("unsupported response action")
    return ResponsePlan(action, dry_run, True, reason)
