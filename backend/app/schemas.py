from datetime import datetime
from typing import List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

_URL_MAX_LEN = 2048


def _validate_url(v: str) -> str:
    """Reject empty/garbage/oversized input before it reaches feature
    extraction -- min_length=4 alone lets "asdf" through as a "URL"."""
    v = v.strip()
    if not v or " " in v:
        raise ValueError("Enter a valid website URL, e.g. https://example.com")
    if len(v) > _URL_MAX_LEN:
        raise ValueError(f"URL too long (max {_URL_MAX_LEN} characters)")
    raw = v if v.lower().startswith(("http://", "https://")) else "http://" + v
    host = urlparse(raw).netloc.split("@")[-1].split(":")[0]
    if not host or "." not in host:
        raise ValueError("Enter a valid website URL, e.g. https://example.com")
    return v


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

    _check_url = field_validator("url")(_validate_url)

class ReportURLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        examples=["https://example-phishing.com"]
    )

    attack_type: Optional[str] = None

    report_reason: Optional[str] = None

    detection_reason: Optional[str] = None

    _check_url = field_validator("url")(_validate_url)

class BatchRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=100)

    _check_urls = field_validator("urls")(
        lambda cls, v: [_validate_url(u) for u in v]
    )


class ShapContribution(BaseModel):
    feature: str
    shap_value: float


class LimeRule(BaseModel):
    rule: str
    weight: float


class DetectionOut(BaseModel):
    id: int
    url: str
    prediction: str
    label: int
    confidence: float
    phishing_probability: float
    risk_level: str
    model_used: str
    created_at: datetime
    ip_address: Optional[str] = None

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
