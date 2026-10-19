import ipaddress
import re
from datetime import datetime
from typing import List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

_URL_MAX_LEN = 2048
_PASSWORD_MIN_LEN = 8
_PASSWORD_SPECIAL_CHARS = r"""!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?"""


def _validate_password_strength(v: str) -> str:
    """Enforce min length + upper/lower/digit/special, reporting every
    missing requirement at once so the frontend can render a checklist."""
    missing = []
    if len(v) < _PASSWORD_MIN_LEN:
        missing.append(f"at least {_PASSWORD_MIN_LEN} characters")
    if not re.search(r"[A-Z]", v):
        missing.append("an uppercase letter")
    if not re.search(r"[a-z]", v):
        missing.append("a lowercase letter")
    if not re.search(r"\d", v):
        missing.append("a number")
    if not re.search(f"[{_PASSWORD_SPECIAL_CHARS}]", v):
        missing.append("a special character")
    if missing:
        raise ValueError("Password must contain " + ", ".join(missing))
    return v


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def _validate_url(v: str) -> str:
    """Reject empty/garbage/oversized input before it reaches feature
    extraction -- min_length=4 alone lets "asdf" through as a "URL".

    An address typed without a scheme ("inti.edu.my") is returned as
    https://, the scheme Chrome itself tries first for a typed address.
    Checking it as http:// instead made the missing-HTTPS signal dominate
    the verdict of well-known sites the user never asked about over HTTP."""
    v = v.strip()
    if not v or " " in v:
        raise ValueError("Enter a valid website URL, e.g. https://example.com")
    if len(v) > _URL_MAX_LEN:
        raise ValueError(f"URL too long (max {_URL_MAX_LEN} characters)")
    raw = v if v.lower().startswith(("http://", "https://")) else "https://" + v
    host = urlparse(raw).netloc.split("@")[-1].split(":")[0].lower()
    if host == "localhost" or host.endswith(".localhost") or _is_private_ip(host):
        # Same rule as the Chrome extension: local/LAN addresses have no
        # public domain for the model to judge, so they are never scanned.
        raise ValueError(
            "Local or private network addresses (such as localhost or "
            "192.168.x.x) can't be scanned - enter a public website URL."
        )
    if not host or "." not in host:
        raise ValueError("Enter a valid website URL, e.g. https://example.com")
    return raw


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=_PASSWORD_MIN_LEN, max_length=128)

    _check_password = field_validator("password")(_validate_password_strength)


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


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., pattern=r"^\d{6}$")
    new_password: str = Field(..., min_length=_PASSWORD_MIN_LEN, max_length=128)

    _check_new_password = field_validator("new_password")(_validate_password_strength)


class AdminCreateUser(BaseModel):
    """Payload for POST /api/admin/users - admin manually creates an account."""
    full_name: str = Field(..., min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=_PASSWORD_MIN_LEN, max_length=128)
    role: Literal["user", "admin"] = "user"

    _check_password = field_validator("password")(_validate_password_strength)


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
    last_login_at: Optional[datetime] = None
    last_logout_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=120)
    email: Optional[EmailStr] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=_PASSWORD_MIN_LEN, max_length=128)

    _check_new_password = field_validator("new_password")(_validate_password_strength)


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
    attack_type: Optional[str] = None
    created_at: datetime
    ip_address: Optional[str] = None
    source: str = "website"

    model_config = ConfigDict(from_attributes=True)

class ReportedURLOut(BaseModel):
    id: int
    url: str
    attack_type: Optional[str] = None
    detection_reason: Optional[str] = None
    status: str = "pending"
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
