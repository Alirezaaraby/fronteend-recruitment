from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import date, datetime, timedelta
import jwt
import random
import string

tags_metadata = [
    {"name": "auth", "description": "Registration, OTP verification, login, and token refresh."},
    {"name": "profile", "description": "Manage the current user's profile."},
    {"name": "report", "description": "Sample sales report for the current user."},
    {"name": "projects", "description": "Paginated projects listing (public)."},
]

app = FastAPI(
    title="Backend Test API",
    description=(
        "API for auth, profile management, reports, and a paginated projects listing.\n\n"
        "Use the Authorize button to provide a Bearer access token after logging in."
    ),
    version="1.0.0",
    contact={
        "name": "Backend Test",
        "email": "support@example.com",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    openapi_tags=tags_metadata,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ----- In-Memory Storage (replace with DB in production) -----
users_db = {}
otp_db = {}
refresh_tokens_db = {}
projects_db = []

# ----- JWT Settings -----
SECRET_KEY = "change_this_secret_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

auth_bearer = HTTPBearer(auto_error=True)

# ----- Pydantic Models -----
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class Profile(BaseModel):
    first_name: str
    last_name: str
    username: str
    date_of_birth: date
    profile_picture: str

class UserResponse(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    username: str
    date_of_birth: Optional[date] = None
    profile_picture: Optional[str] = None

class Customer(BaseModel):
    name: str
    email: EmailStr

class ProjectOut(BaseModel):
    Customer: Customer
    status: str
    date: str

# ----- Helper Functions -----
def generate_fake_otp(length: int = 6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def get_user_by_email(email: str):
    user = users_db.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(email: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    token = jwt.encode({"sub": email, "type": "refresh", "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    # Track refresh token in-memory so it can be invalidated/rotated if needed
    refresh_tokens_db[token] = {"email": email, "exp": expire}
    return token

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_bearer)):
    token = credentials.credentials
    payload = decode_access_token(token)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return get_user_by_email(email)

def seed_projects_once() -> None:
    if projects_db:
        return
    now = datetime.utcnow().replace(microsecond=0)
    statuses = ["Fulfilled", "Declined"]
    names = [
        "Acme Corp", "Globex", "Initech", "Umbrella", "Soylent",
        "Stark Industries", "Wayne Enterprises", "Wonka", "Hooli",
        "Oscorp", "Aperture", "Cyberdyne"
    ]
    domains = [
        "acme.com", "globex.com", "initech.com", "umbrella.com", "soylent.com",
        "stark.com", "wayne.com", "wonka.com", "hooli.com",
        "oscorp.com", "aperture.com", "cyberdyne.com"
    ]
    for i in range(12):
        projects_db.append({
            "Customer": {
                "name": names[i],
                "email": f"contact@{domains[i]}"
            },
            "status": statuses[i % len(statuses)],
            "date": (now - timedelta(days=i)).isoformat() + "Z",
        })

# ----- Routes -----
@app.post("/auth/register", tags=["auth"])
def register(request: RegisterRequest):
    if request.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    otp = generate_fake_otp()
    otp_db[request.email] = {"otp": otp, "password": request.password}
    return {"message": "OTP sent", "otp": otp}  # in production, send via email/SMS

@app.post("/auth/verify-otp", tags=["auth"])
def verify_otp(request: VerifyOTPRequest):
    record = otp_db.get(request.email)
    if not record or record["otp"] != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Create user in DB with temporary info
    users_db[request.email] = {
        "email": request.email,
        "password": record["password"],
        "first_name": "",
        "last_name": "",
        "username": "",
        "date_of_birth": None,
        "profile_picture": None
    }
    otp_db.pop(request.email)
    return {"message": "Registration successful"}

@app.post("/auth/login", tags=["auth"])
def login(request: LoginRequest):
    user = users_db.get(request.email)
    if not user or user["password"] != request.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Access token
    access_expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token({"sub": request.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    # Refresh token
    refresh_expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(request.email, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

    return {
        "access_token": access_token,
        "access_token_expires_at": access_expires_at.replace(microsecond=0).isoformat() + "Z",
        "refresh_token": refresh_token,
        "refresh_token_expires_at": refresh_expires_at.replace(microsecond=0).isoformat() + "Z",
        "token_type": "bearer",
    }

@app.post("/auth/refresh", tags=["auth"])
def refresh_token_endpoint(token: str):
    # Validate refresh token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        # Remove expired token if present
        refresh_tokens_db.pop(token, None)
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Not a refresh token")

    # Check if token is tracked (simple in-memory invalidation)
    tracked = refresh_tokens_db.get(token)
    if not tracked:
        raise HTTPException(status_code=401, detail="Refresh token invalidated")

    email = payload.get("sub")
    if not email or email not in users_db:
        raise HTTPException(status_code=401, detail="Unknown user for refresh token")

    # Rotate refresh token: invalidate old one and issue new pair
    refresh_tokens_db.pop(token, None)

    new_access_expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token({"sub": email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    new_refresh_expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    new_refresh_token = create_refresh_token(email, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

    return {
        "access_token": new_access_token,
        "access_token_expires_at": new_access_expires_at.replace(microsecond=0).isoformat() + "Z",
        "refresh_token": new_refresh_token,
        "refresh_token_expires_at": new_refresh_expires_at.replace(microsecond=0).isoformat() + "Z",
        "token_type": "bearer",
    }

# ----- Profile Endpoints -----
@app.get("/me", response_model=UserResponse, tags=["profile"])
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.post("/me", tags=["profile"])
def create_me(user: Profile, current_user: dict = Depends(get_current_user)):
    db_user = get_user_by_email(current_user["email"])
    db_user.update(user.dict())
    return {"message": "Profile created/updated", "user": db_user}

@app.put("/me", tags=["profile"])
def update_me(user: Profile, current_user: dict = Depends(get_current_user)):
    db_user = get_user_by_email(current_user["email"])
    db_user.update(user.dict())
    return {"message": "Profile updated", "user": db_user}

@app.get("/report", tags=["report"])
def get_sales_report(current_user: dict = Depends(get_current_user)):
    # Create 12 sample sales entries with ISO datetime
    now = datetime.utcnow()
    samples = []
    for i in range(12):
        entry_date = (now - timedelta(days=i)).replace(microsecond=0).isoformat() + "Z"
        amount_value = random.randint(100, 5000)
        samples.append({
            "amount": f"{amount_value}$",
            "date": entry_date,
        })
    # Return in chronological order (oldest first)
    return list(reversed(samples))

# ----- Projects Endpoint (Paginated) -----
@app.get("/projects", response_model=dict, tags=["projects"])
def list_projects(page: int = 1):
    seed_projects_once()
    per_page = 4
    total = len(projects_db)
    total_pages = 3
    if total != 12:
        # Ensure fixed-size catalogue per requirements
        raise HTTPException(status_code=500, detail="Projects catalogue misconfigured")
    if page < 1 or page > total_pages:
        raise HTTPException(status_code=400, detail="Page must be between 1 and 3")
    start = (page - 1) * per_page
    end = start + per_page
    items = projects_db[start:end]
    return {
        "items": items,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "total": total,
    }
