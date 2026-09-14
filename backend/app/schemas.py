from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class RegisterResponse(BaseModel):
    """Register no longer auto-logs the user in - it just creates the
    account and returns the record. The frontend shows a success
    message and redirects to /login so the user signs in intentionally.
    """
    message: str
    user: "UserOut"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"


class AdminCreateUser(BaseModel):
    """Payload for POST /api/admin/users - admin manually creates an account."""
    full_name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)
    role: Literal["user", "admin"] = "user"


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
class UserOut(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=120)
    email: Optional[EmailStr] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6, max_length=128)


class AdminUserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=120)
    email: Optional[EmailStr] = None
    role: Optional[Literal["user", "admin"]] = None
    is_active: Optional[bool] = None


# ---------------------------------------------------------------------------
# Prediction / detection
# ---------------------------------------------------------------------------
class URLRequest(BaseModel):
    url: str = Field(..., min_length=4, examples=["https://example.com"])

class ReportURLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        examples=["https://example-phishing.com"]
    )

    attack_type: Optional[str] = None

    report_reason: Optional[str] = None

    detection_reason: Optional[str] = None

class BatchRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=100)


class ShapContribution(BaseModel):
    feature: str
    shap_value: float


class LimeRule(BaseModel):
    rule: str
    weight: float

class PhishingEvidence(BaseModel):
    """
    Evidence explanation generated from phishing_type.py
    """

    technique: Optional[str] = None

    category: Optional[str] = None

    evidence: str

class DetectionOut(BaseModel):
    id: int
    url: str
    prediction: str
    label: int

    # ML confidence
    confidence: float

    phishing_probability: float

    risk_level: str

    model_used: str

    created_at: datetime

    ip_address: Optional[str] = None


    # =====================================================
    # Phishing explanation information
    # Added in Step 2
    # =====================================================

    phishing_category: Optional[str] = None

    rule_confidence: Optional[str] = None

    category_confidence: Optional[int] = None

    evidence_strength: Optional[str] = None

    phishing_summary: Optional[str] = None

    phishing_techniques: Optional[List[str]] = None

    category_evidence: Optional[List[PhishingEvidence]] = None

    technique_evidence: Optional[List[PhishingEvidence]] = None

    def model_post_init(self, __context):
        import json

        if isinstance(self.phishing_techniques, str):
            try:
                self.phishing_techniques = json.loads(
                    self.phishing_techniques
                )
            except Exception:
                self.phishing_techniques = []

        if isinstance(self.category_evidence, str):
            try:
                self.category_evidence = json.loads(
                    self.category_evidence
                )
            except Exception:
                self.category_evidence = []

        if isinstance(self.technique_evidence, str):
            try:
                self.technique_evidence = json.loads(
                    self.technique_evidence
                )
            except Exception:
                self.technique_evidence = []

    model_config = ConfigDict(from_attributes=True)

class ReportedURLOut(BaseModel):
    id: int
    url: str
    attack_type: Optional[str] = None
    detection_reason: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ExtensionReportCreate(BaseModel):
    url: str
    attack_type: Optional[str] = None
    detection_reason: Optional[str] = None
    browser_info: Optional[str] = None


class ExtensionReportOut(BaseModel):
    id: int
    url: str
    attack_type: Optional[str] = None
    detection_reason: Optional[str] = None
    browser_info: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    created_at: datetime
    reviewed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class DetectionWithUser(DetectionOut):
    user_email: str
    user_name: str


TokenResponse.model_rebuild()
RegisterResponse.model_rebuild()
