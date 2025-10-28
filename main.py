from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import date, datetime, timedelta
import jwt
import random
import string

app = FastAPI()

# ----- In-Memory Storage (replace with DB in production) -----
users_db = {}
otp_db = {}

# ----- JWT Settings -----
SECRET_KEY = "change_this_secret_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

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

# ----- Routes -----
@app.post("/auth/register")
def register(request: RegisterRequest):
    if request.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    otp = generate_fake_otp()
    otp_db[request.email] = {"otp": otp, "password": request.password}
    return {"message": "OTP sent", "otp": otp}  # in production, send via email/SMS

@app.post("/auth/verify-otp")
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

@app.post("/auth/login")
def login(request: LoginRequest):
    user = users_db.get(request.email)
    if not user or user["password"] != request.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": request.email})
    return {"access_token": access_token, "token_type": "bearer"}

# ----- Profile Endpoints -----
@app.get("/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.post("/me")
def create_me(user: Profile, current_user: dict = Depends(get_current_user)):
    db_user = get_user_by_email(current_user["email"])
    db_user.update(user.dict())
    return {"message": "Profile created/updated", "user": db_user}

@app.put("/me")
def update_me(user: Profile, current_user: dict = Depends(get_current_user)):
    db_user = get_user_by_email(current_user["email"])
    db_user.update(user.dict())
    return {"message": "Profile updated", "user": db_user}
