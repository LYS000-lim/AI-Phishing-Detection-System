import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .auth import create_access_token, current_user, hash_password, verify_password
from .database import get_db
from .email_utils import send_password_reset_email
from .models import PasswordResetToken, User
from .schemas import (
    ForgotPasswordRequest, LoginRequest, RegisterRequest, RegisterResponse,
    ResetPasswordRequest, TokenResponse, UserOut,
)

RESET_TOKEN_TTL_MINUTES = 30
FRONTEND_URL = os.environ.get("PHISHGUARD_FRONTEND_URL", "http://localhost:5173")


def _hash_reset_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    exists = db.query(User).filter(User.email == payload.email.lower()).first()
    if exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This email has already been registered. Please use another email.",
        )

    # First-ever registered account becomes the admin, so the app is
    # usable out of the box without a seeding step.
    role = "admin" if db.query(User).count() == 0 else "user"

    user = User(
        full_name=payload.full_name.strip(),
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Do NOT auto-log-in. Return the created user and a success message;
    # the frontend shows the message and redirects to /login so the user
    # signs in intentionally.
    return RegisterResponse(
        message="Your account has been created successfully. "
                "Please sign in to continue.",
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Contact an administrator.",
        )
    user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(user)
    token = create_access_token(user)
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/logout")
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)):
    # JWTs are stateless. The client discards the token; this endpoint
    # exists so the frontend has a definitive "log me out" call for its
    # Logout confirmation screen (and to record last_logout_at).
    user.last_logout_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    return {"message": f"Goodbye, {user.full_name}. You have been logged out."}


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Always return the same generic message, whether or not the email is
    # registered, so this endpoint can't be used to enumerate accounts.
    generic_response = {
        "message": "If that email is registered, a password reset link has been sent.",
    }

    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not user.is_active:
        return generic_response

    raw_token = secrets.token_urlsafe(32)
    reset_row = PasswordResetToken(
        user_id=user.id,
        token_hash=_hash_reset_token(raw_token),
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None)
        + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
    )
    db.add(reset_row)
    db.commit()

    reset_link = f"{FRONTEND_URL}/reset-password?token={raw_token}"
    send_password_reset_email(user.email, reset_link)

    return generic_response


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_hash = _hash_reset_token(payload.token)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    reset_row = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .first()
    )
    if not reset_row:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link is invalid or has expired. Please request a new one.",
        )

    user = db.query(User).filter(User.id == reset_row.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link is invalid or has expired. Please request a new one.",
        )

    user.password_hash = hash_password(payload.new_password)
    reset_row.used_at = now
    db.commit()
