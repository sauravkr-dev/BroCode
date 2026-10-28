from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import Optional

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)

class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str
    model_config = ConfigDict(from_attributes=True)

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class ApplicationIn(BaseModel):
    institution_name: str = Field(min_length=2, max_length=240)
    institution_code: str = Field(default="", max_length=80)
    application_type: str = Field(default="Extension of Approval", max_length=80)
    academic_year: str = Field(default="2026-27", pattern=r"^20\d{2}-\d{2}$")
    programme: str = Field(default="", max_length=160)
    current_intake: Optional[int] = Field(default=None, ge=0, le=100000)
    proposed_intake: Optional[int] = Field(default=None, ge=0, le=100000)

class StatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(UNDER_REVIEW|DEFICIENCY_RAISED|RECTIFICATION_SUBMITTED|OFFICER_RECOMMENDATION_RECORDED|CLOSED)$")

class FindingOut(BaseModel):
    id: int
    rule_id: str
    severity: str
    result: str
    message: str
    source_reference: str
    evidence: dict

class ApplicationOut(BaseModel):
    id: int
    institution_name: str
    institution_code: str
    application_type: str
    academic_year: str
    programme: str
    current_intake: Optional[int]
    proposed_intake: Optional[int]
    status: str
    owner_id: int
    assigned_officer_id: Optional[int] = None
    submission_version: int = 1
    model_config = ConfigDict(from_attributes=True)

class OfficerReviewIn(BaseModel):
    action: str = Field(pattern=r"^(REVIEW_NOTE|DEFICIENCY_REQUEST|CORRECTION_ACCEPTED|RECOMMENDATION)$")
    notes: str = Field(min_length=1, max_length=5000)
    finding_references: Optional[list[str]] = Field(default_factory=list)
    correction_instructions: Optional[str] = Field(default="", max_length=5000)

class OfficerReviewOut(BaseModel):
    id: int
    application_id: int
    officer_id: int
    action: str
    notes: str
    finding_references: Optional[list[str]] = None
    correction_instructions: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class AssignOfficerIn(BaseModel):
    officer_id: Optional[int] = None

class UserCreate(BaseModel):
    email: EmailStr
    name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=8, max_length=200)
    role: str = Field(default="institution", pattern=r"^(institution|officer|admin)$")

class UserUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    role: Optional[str] = Field(default=None, pattern=r"^(institution|officer|admin)$")
    active: Optional[bool] = None
