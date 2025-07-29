from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text,ForeignKey,Float,BigInteger
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'  # Plural table names are conventional

    # Basic user info
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=True, unique=True, index=True)  # Optional but recommended
    password = Column(String(255), nullable=False)  # Bcrypt needs ~60 chars, 255 for safety

    # Profile information
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    bio = Column(Text, nullable=True)
    profile_picture_url = Column(String(500), nullable=True)

    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Strava Integration Fields
    strava_user_id = Column(String(50), nullable=True, unique=True, index=True)
    strava_access_token = Column(String(255), nullable=True)
    strava_refresh_token = Column(String(255), nullable=True)
    strava_token_expires_at = Column(BigInteger, nullable=True)
    strava_connected_at = Column(DateTime, nullable=True)

    # Privacy settings
    profile_public = Column(Boolean, default=True, nullable=False)
    workouts_public = Column(Boolean, default=True, nullable=False)

    # Social features
    total_workouts = Column(Integer, default=0, nullable=False)
    total_distance = Column(Integer, default=0, nullable=False)  # in meters
    total_time = Column(Integer, default=0, nullable=False)  # in seconds
    activities = relationship(
        "Activity",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="Activity.timestamp.desc()"
    )

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', strava_connected={bool(self.strava_user_id)})>"

    @property
    def is_strava_connected(self):
        """Check if user has connected Strava account"""
        return bool(self.strava_user_id and self.strava_access_token)

    @property
    def strava_token_expired(self):
        """Check if Strava token needs refresh"""
        if not self.strava_token_expires_at:
            return True
        return datetime.utcnow() > self.strava_token_expires_at


class Activity(Base):
    __tablename__ = "activities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    strava_id = Column(BigInteger, nullable=False, index=True, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    description = Column(Text, nullable=True)
    distance = Column(Float, nullable=True)        # in km
    average_speed = Column(Float, nullable=True)   # km/h
    moving_time = Column(Integer, nullable=True)   # in seconds
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="activities")