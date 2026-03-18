from __future__ import annotations

from typing import Optional, Literal, Dict, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select

from ..db import get_db
from ..models import User
from ..security import decode_token

router = APIRouter()

_ALLOWED_USER_TYPES = {"investor", "founder", "enterprise", "developer", "other"}
_ALLOWED_INTENTS = {"exploring", "company_eval", "investment", "partnership", "curious"}

def _current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload

class OnboardingIn(BaseModel):
    company: Optional[str] = Field(default=None, max_length=200)
    role: Optional[str] = Field(default=None, max_length=200)
    user_type: Literal["investor","founder","enterprise","developer","other"]
    intent: Literal["exploring","company_eval","investment","partnership","curious"]
    notes: Optional[str] = Field(default=None, max_length=1200)
    onboarding_completed: bool = True

@router.post("/api/user/onboarding")
def complete_onboarding(inp: OnboardingIn, user=Depends(_current_user), db: Session = Depends(get_db)):
    uid = user.get("sub")
    u = db.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not (u.role == "admin" or getattr(u, "approved_at", None)):
        raise HTTPException(status_code=403, detail="Manual approval required before onboarding.")
    u.company = (inp.company or "").strip() or None
    u.profile_role = (inp.role or "").strip() or None
    u.user_type = inp.user_type
    u.intent = inp.intent
    u.notes = (inp.notes or "").strip() or None
    u.onboarding_completed = bool(inp.onboarding_completed)
    db.add(u)
    db.commit()
    return {
        "ok": True,
        "user": {
            "id": u.id,
            "company": u.company,
            "profile_role": u.profile_role,
            "user_type": u.user_type,
            "intent": u.intent,
            "notes": u.notes,
            "onboarding_completed": bool(u.onboarding_completed),
        },
    }
