import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .auth import create_access_token, current_user, hash_password, verify_password
from .database import get_db
from .email_utils import send_password_reset_code
from .models import PasswordResetToken, User
from .schemas import (
    ForgotPasswordRequest, LoginRequest, RegisterRequest, RegisterResponse,
    ResetPasswordRequest, TokenResponse, UserOut,
)

RESET_CODE_TTL_MINUTES = 10
MAX_CODE_ATTEMPTS = 5


def _hash_reset_code(user_id: int, code: str) -> str:
    # Salted with the user id so two users' identical codes never collide
    # on the unique token_hash column.
    return hashlib.sha256(f"{user_id}:{code}".encode("utf-8")).hexdigest()

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
        "message": "If that email is registered, a verification code has been sent.",
    }

    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not user.is_active:
        return generic_response

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Requesting a new code invalidates any earlier unused one.
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).update({PasswordResetToken.used_at: now})

    code = f"{secrets.randbelow(1_000_000):06d}"
    db.add(PasswordResetToken(
        user_id=user.id,
        token_hash=_hash_reset_code(user.id, code),
        expires_at=now + timedelta(minutes=RESET_CODE_TTL_MINUTES),
    ))
    db.commit()

    send_password_reset_code(user.email, code, RESET_CODE_TTL_MINUTES)
    return generic_response


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    invalid = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="This code is invalid or has expired. Please request a new one.",
    )
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not user.is_active:
        raise invalid

    reset_row = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .order_by(PasswordResetToken.created_at.desc())
        .first()
    )
    if not reset_row:
        raise invalid

    if not hmac.compare_digest(reset_row.token_hash, _hash_reset_code(user.id, payload.code)):
        # Limit guesses: a 6-digit code is only safe with an attempt cap.
        reset_row.attempts = (reset_row.attempts or 0) + 1
        if reset_row.attempts >= MAX_CODE_ATTEMPTS:
            reset_row.used_at = now
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Too many incorrect attempts. Please request a new code.",
            )
        db.commit()
        left = MAX_CODE_ATTEMPTS - reset_row.attempts
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incorrect code. {left} attempt{'s' if left != 1 else ''} left.",
        )

    user.password_hash = hash_password(payload.new_password)
    reset_row.used_at = now
    db.commit()
