"""
models.py
Data model + schema definition for a Cybersecurity Incident Report.

Keeping this as a plain dataclass (rather than trusting raw dicts all the
way through the app) means every field that reaches report_generator.py
has already been type-checked and length-checked by security.py.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any


# Allowed values for constrained fields. Anything outside this list is
# rejected by security.validate_incident_data() rather than silently
# accepted -- this is the "allow-list, not block-list" principle applied
# to structured fields.
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Informational"]
STATUS_VALUES = ["Open", "Investigating", "Contained", "Eradicated", "Recovered", "Closed"]
TLP_LEVELS = ["TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"]

# Max lengths guard against pathological input (denial-of-service via
# giant payloads, or someone trying to smuggle a huge blob into a PDF).
FIELD_LIMITS = {
    "incident_id": 64,
    "title": 200,
    "reported_by": 100,
    "report_author": 100,
    "description": 5000,
    "root_cause": 3000,
    "impact_assessment": 3000,
    "recommendations": 3000,
    "affected_systems": 2000,
}

TIMELINE_ENTRY_LIMIT = 500      # max length of a single timeline event
IOC_ENTRY_LIMIT = 300           # max length of a single IOC line
MAX_TIMELINE_EVENTS = 200
MAX_IOCS = 200


@dataclass
class TimelineEvent:
    timestamp: str
    description: str


@dataclass
class IncidentReport:
    incident_id: str
    title: str
    severity: str
    status: str
    classification: str
    reported_by: str
    report_author: str
    date_reported: str
    date_occurred: str
    affected_systems: str
    description: str
    timeline: List[TimelineEvent] = field(default_factory=list)
    indicators_of_compromise: List[str] = field(default_factory=list)
    impact_assessment: str = ""
    containment_actions: str = ""
    eradication_actions: str = ""
    recovery_actions: str = ""
    root_cause: str = ""
    recommendations: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
