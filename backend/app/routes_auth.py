"""Auth endpoints: register, login, current user."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .auth import create_access_token, current_user, hash_password, verify_password
from .database import get_db
from .models import User
from .schemas import (
    LoginRequest, RegisterRequest, RegisterResponse,
    TokenResponse, UserOut,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    exists = db.query(User).filter(User.email == payload.email.lower()).first()
    if exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists",
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
    token = create_access_token(user)
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/logout")
def logout(user: User = Depends(current_user)):
    # JWTs are stateless. The client discards the token; this endpoint
    # exists so the frontend has a definitive "log me out" call for its
    # Logout confirmation screen.
    return {"message": f"Goodbye, {user.full_name}. You have been logged out."}
