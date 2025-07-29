from dotenv import load_dotenv
load_dotenv()

import httpx
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from sqlalchemy.orm import Session
from models import User


class StravaService:
    def __init__(self):
        self.client_id = os.getenv("STRAVA_CLIENT_ID")
        self.client_secret = os.getenv("STRAVA_CLIENT_SECRET")
        self.redirect_uri = os.getenv("STRAVA_REDIRECT_URI")
        self.base_url = "https://www.strava.com/api/v3"
        self.auth_url = "https://www.strava.com/oauth"

        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            raise ValueError("Missing Strava configuration. Check your environment variables.")

    def get_authorization_url(self, state: str = None) -> str:
        """Generate Strava OAuth authorization URL"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "read,activity:read_all,profile:read_all",
            "approval_prompt": "auto"
        }

        if state:
            params["state"] = state

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{self.auth_url}/authorize?{query_string}"

    async def exchange_code_for_tokens(self, code: str) -> Dict:
        """Exchange authorization code for access and refresh tokens"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_url}/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code"
                }
            )

            if response.status_code != 200:
                raise Exception(f"Failed to exchange code for tokens: {response.text}")

            return response.json()

    async def refresh_access_token(self, refresh_token: str) -> Dict:
        """Refresh expired access token"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.auth_url}/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token"
                }
            )

            if response.status_code != 200:
                raise Exception(f"Failed to refresh token: {response.text}")

            return response.json()

    async def get_authenticated_athlete(self, access_token: str) -> Dict:
        """Get the authenticated athlete's profile"""
        headers = {"Authorization": f"Bearer {access_token}"}

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/athlete",
                headers=headers
            )

            if response.status_code != 200:
                raise Exception(f"Failed to get athlete info: {response.text}")

            return response.json()

    async def get_athlete_activities(
            self,
            access_token: str,
            page: int = 1,
            per_page: int = 30,
            after: Optional[datetime] = None,
            before: Optional[datetime] = None
    ) -> List[Dict]:
        """Get athlete's activities"""
        headers = {"Authorization": f"Bearer {access_token}"}
        params = {
            "page": page,
            "per_page": per_page
        }

        if after:
            params["after"] = int(after.timestamp())
        if before:
            params["before"] = int(before.timestamp())

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/athlete/activities",
                headers=headers,
                params=params
            )

            if response.status_code == 401:
                raise Exception("Unauthorized - token may be expired")
            elif response.status_code != 200:
                raise Exception(f"Failed to get activities: {response.text}")

            return response.json()

    async def get_activity_details(self, access_token: str, activity_id: str) -> Dict:
        """Get detailed information about a specific activity"""
        headers = {"Authorization": f"Bearer {access_token}"}

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/activities/{activity_id}",
                headers=headers
            )

            if response.status_code != 200:
                raise Exception(f"Failed to get activity details: {response.text}")

            return response.json()

    def store_strava_tokens(self, user: User, token_data: Dict, db: Session):
        """Store Strava tokens and user info in database"""
        user.strava_user_id = str(token_data["athlete"]["id"])
        user.strava_access_token = token_data["access_token"]
        user.strava_refresh_token = token_data["refresh_token"]
        user.strava_token_expires_at = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])
        user.strava_connected_at = datetime.utcnow()
        user.updated_at = datetime.utcnow()

        db.commit()

    async def ensure_valid_token(self, user: User, db: Session) -> str:
        """Ensure user has a valid access token, refresh if needed"""
        if not user.strava_access_token:
            raise Exception("User not connected to Strava")

        # Check if token is expired
        if user.strava_token_expired:
            if not user.strava_refresh_token:
                raise Exception("No refresh token available")

            # Refresh the token
            token_data = await self.refresh_access_token(user.strava_refresh_token)
            self.store_strava_tokens(user, token_data, db)

        return user.strava_access_token


# Create a global instance
strava_service = StravaService()