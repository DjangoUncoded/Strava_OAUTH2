import urllib
import time
import os
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, Request, Response, Form
from dotenv import load_dotenv

import requests
from jose import jwt, JWTError
from passlib.context import CryptContext
from typing import Optional

from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from database import Session_Local, engine
import models
from sqlalchemy.orm import Session
from models import User,Activity
load_dotenv()

# Initialize FastAPI and templates
app = FastAPI()
templates = Jinja2Templates(directory="templates")
models.Base.metadata.create_all(bind=engine)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security utilities
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginForm(BaseModel):
    username: str
    password: str


# Database dependency
def get_db():
    db = Session_Local()
    try:
        yield db
    finally:
        db.close()



# Helper Functions

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        # This will trigger a redirect to the login page from the frontend if needed
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token: No username")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token: JWTError")

    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user




# Authentication Routes


@app.get("/")
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/login")
async def login(
        response: Response,
        username: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db)
):
    user = authenticate_user(username, password, db)
    if not user:
        # Ideally, you'd return an error message to the login page
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username})

    response = RedirectResponse(url="/protected", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        path="/"
    )
    return response


@app.get("/signup")
async def signup_form(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})


@app.post("/signup")
async def signup(
        username: str = Form(...),
        password: str = Form(...),
        email: str = Form(...),
        firstname: str = Form(...),
        lastname: str = Form(...),
        db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if user:
        # return an error message to the signup page
        raise HTTPException(status_code=400, detail="Username already exists")

    created_user = User(
        username=username,
        password=bcrypt_context.hash(password),
        first_name=firstname,
        last_name=lastname,
        email=email,
    )
    db.add(created_user)
    db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.get("/protected")
async def protected_route(request: Request, user: User = Depends(get_current_user)):
    # The Depends(get_current_user) will handle authentication.
    # If the user is not authenticated, it will raise a 401 error.
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})


@app.get("/logout")
async def logout_page(request: Request):
    return templates.TemplateResponse("Logout.html", {"request": request})


@app.post("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(key="access_token")
    return response



# Strava Integration
# --------------------------

STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET")
STRAVA_REDIRECT_URI = os.getenv("STRAVA_REDIRECT_URI")

"""First Time Generation of A token"""

def exchange_strava_code_for_token(code: str) -> dict:
    url = "https://www.strava.com/api/v3/oauth/token"
    data = {
        "client_id": STRAVA_CLIENT_ID,
        "client_secret": STRAVA_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()

"""Generating new token since the orgnal token Expires every 6 hours"""
def refresh_strava_token(user: User, db: Session) -> Optional[str]:
    """Refreshes the Strava token and updates the user in the database."""
    if not user.strava_refresh_token:
        return None
    try:
        url = "https://www.strava.com/api/v3/oauth/token"
        data = {
            "client_id": STRAVA_CLIENT_ID,
            "client_secret": STRAVA_CLIENT_SECRET,
            "refresh_token": user.strava_refresh_token,
            "grant_type": "refresh_token",
        }
        resp = requests.post(url, data=data)
        resp.raise_for_status()
        token_data = resp.json()

        user.strava_access_token = token_data["access_token"]
        user.strava_refresh_token = token_data["refresh_token"]
        user.strava_token_expires_at = token_data["expires_at"]
        db.commit()
        return token_data["access_token"]
    except requests.RequestException:
        # Could log the error here
        return None


def get_valid_strava_token(user: User, db: Session) -> Optional[str]:
    """Get a valid Strava access token, refreshing if needed."""
    if not user.strava_access_token or not user.strava_token_expires_at:
        return None

    # Check if token is expired (with 5-minute buffer)

    if user.strava_token_expires_at < (int(time.time()) + 300):
        return refresh_strava_token(user, db)

    return user.strava_access_token


@app.get("/strava/auth")
def strava_auth():
    params = {
        "client_id": STRAVA_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": STRAVA_REDIRECT_URI,
        "approval_prompt": "force",
        "scope": "read,activity:read_all"
    }
    authorize_url = f"https://www.strava.com/oauth/authorize?{urllib.parse.urlencode(params)}"
    return RedirectResponse(authorize_url)


@app.get("/strava/callback")
async def strava_callback(
        code: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    token_data = exchange_strava_code_for_token(code)

    user.strava_access_token = token_data["access_token"]
    user.strava_refresh_token = token_data["refresh_token"]
    user.strava_token_expires_at = token_data["expires_at"]
    db.commit()

    return RedirectResponse(url="/protected", status_code=303)



# Strava API Proxy Endpoints


@app.get("/api/strava/profile")
async def get_strava_profile(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    access_token = get_valid_strava_token(user, db)
    if not access_token:
        return {"connected": False, "error": "Not connected to Strava or token invalid."}

    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get("https://www.strava.com/api/v3/athlete", headers=headers, timeout=10)
        resp.raise_for_status()
        return {"connected": True, "profile": resp.json()}
    except requests.RequestException as e:
        return {"connected": False, "error": f"Failed to fetch Strava profile: {e}"}


@app.get("/api/strava/stats")
async def get_strava_stats(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    access_token = get_valid_strava_token(user, db)
    if not access_token:
        return {"connected": False, "error": "Not connected to Strava or token invalid."}

    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        # First get athlete ID from profile
        profile_resp = requests.get("https://www.strava.com/api/v3/athlete", headers=headers, timeout=10)
        profile_resp.raise_for_status()
        athlete_id = profile_resp.json()["id"]

        # Then get stats
        stats_resp = requests.get(f"https://www.strava.com/api/v3/athletes/{athlete_id}/stats", headers=headers,
                                  timeout=10)
        stats_resp.raise_for_status()
        return {"connected": True, "stats": stats_resp.json()}
    except requests.RequestException as e:
        return {"connected": False, "error": f"Failed to fetch Strava stats: {e}"}


@app.get("/api/strava/recent-activities")
async def get_and_store_recent_activities(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    access_token = get_valid_strava_token(user, db)
    if not access_token:
        return {"connected": False, "error": "Not connected to Strava or token invalid."}

    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        params = {"per_page": 5, "page": 1}
        resp = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers, params=params,
                            timeout=10)
        resp.raise_for_status()

        strava_activities_data = resp.json()
        activities = []
        db.query(Activity).filter(Activity.user_id == user.id).delete()

        for act in strava_activities_data:
            activities.append({
                "name": act.get("name"),
                "type": act.get("type"),
                "start_date": act.get("start_date"),
                "distance": round(act.get("distance", 0) / 1000, 2),
                "moving_time": act.get("moving_time"),
                "average_speed": round(act.get("average_speed", 0) * 3.6, 2)
            })

            # Check if activity already exists
            existing_activity = db.query(Activity).filter(
                Activity.strava_id == act.get("id"),
                Activity.user_id == user.id
            ).first()

            if not existing_activity:
                new_activity = Activity(
                    strava_id=act.get("id"),
                    user_id=user.id,
                    moving_time=act.get("moving_time"),
                    average_speed=round(act.get("average_speed", 0) * 3.6, 2),
                    description=act.get("type"),
                    distance=round(act.get("distance", 0) / 1000, 2)
                )
                db.add(new_activity)

        db.commit()
        return {"connected": True, "activities": activities}

    except requests.RequestException as e:
        db.rollback()
        return {"connected": False, "error": f"Failed to fetch Strava activities: {e}"}
    except Exception as e:
        db.rollback()
        return {"connected": False, "error": f"Database error: {e}"}

""""Blogging Page Routes"""
@app.get("/page")
async def get_page(request:Request,user: User = Depends(get_current_user)):
    return templates.TemplateResponse(
        "page.html", {"request": request, "user": user})
