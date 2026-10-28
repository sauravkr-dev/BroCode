import hashlib, json
from sqlalchemy.orm import Session
from sqlalchemy import select
from .models import AuditEvent

def log_event(db: Session, actor_id: int | None, action: str, entity_type: str, entity_id: str, payload: dict | None = None):
    last = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
    previous = last.event_hash if last else "0" * 64
    payload_json = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    material = f"{previous}|{actor_id}|{action}|{entity_type}|{entity_id}|{payload_json}"
    event_hash = hashlib.sha256(material.encode()).hexdigest()
    event = AuditEvent(actor_id=actor_id, action=action, entity_type=entity_type, entity_id=str(entity_id), payload_json=payload_json, previous_hash=previous, event_hash=event_hash)
    db.add(event); db.flush()
    return event
