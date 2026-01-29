from typing import Literal, List
from enum import Enum
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from fastapi import FastAPI, HTTPException, Header, Response
from pydantic import BaseModel, EmailStr, Field
from jwt import encode, decode, InvalidSignatureError

app = FastAPI(title="Radio API", version="1.0.0")

class AuthRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)

class AuthenticatedUser(BaseModel):
    token: str

class WishRequest(BaseModel):
    text: str = Field(min_length=1)

class ReviewRequest(BaseModel):
    host_email: EmailStr
    rating: Literal["positive", "negative"]
    text: str = Field(min_length=1)

class Review(BaseModel):
    review_id: int
    email: EmailStr
    host_email: EmailStr
    rating: Literal["positive", "negative"]
    text: str = Field(min_length=1)

class RatePlaylistRequest(BaseModel):
    playlist: str
    rating: Literal["positive", "negative"]

class CurrentTrack(BaseModel):
    id: str
    title: str
    artist: str
    album: str
    year: int
    duration: int
    coverUrl: str
    playlist: str

class CurrentHost(BaseModel):
    name: str
    email: EmailStr

class Role(str, Enum):
    User = "User"
    Host = "Host"


USERS: dict[str, str] = {
    "host1@radio.com": "host123",
    "host2@radio.com": "host123",
    "user@someemail.com": "user123",
}

ROLES: dict[str, Role] = {
    "host1@radio.com": Role.Host,
    "host2@radio.com": Role.Host,
    "user@someemail.com": Role.User
}

SECRET = "somesecret"

TRACKS: List[CurrentTrack] = [
    CurrentTrack(
        id="track_001",
        title="Fake Track 1",
        artist="Fake Artist 1",
        album="Fake Album 1",
        year=2011,
        duration=244,
        coverUrl="", # TODO base64 image instead of url?
        playlist="90s" # TODO separate endpoint?
    ),
    CurrentTrack(
        id="track_002",
        title="Fake Track 2",
        artist="Fake Artist 2",
        album="Fake Album 2",
        year=2006,
        duration=185,
        coverUrl="",
        playlist="Summer"
    ),
    CurrentTrack(
        id="track_003",
        title="Fake Track 3",
        artist="Fake Artist 3",
        album="Fake Album 3",
        year=2024,
        duration=219,
        coverUrl="",
        playlist="Pop"
    )
]

REVIEWS: List[Review] = [
    Review(
        review_id=1,
        email="listener1@example.com",
        host_email="host1@radio.com",
        rating="positive",
        text="Guter Moderator.",
    ),
    Review(
        review_id=2,
        email="listener2@example.com",
        host_email="host1@radio.com",
        rating="negative",
        text="Zu viel Werbung!",
    ),
    Review(
        review_id=3,
        email="listener3@example.com",
        host_email="host2@radio.com",
        rating="positive",
        text="Der macht gute Witze.",
    ),
]


def decode_token(token: str) -> dict:
    try:
        return decode(token, SECRET, algorithms=["HS256"])
    except InvalidSignatureError:
        raise HTTPException(status_code=401, detail="Token Signature Verification failed")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return parts[1]


def next_review_id() -> int:
    return len(REVIEWS) + 1


@app.post("/login", response_model=AuthenticatedUser)
def login(payload: AuthRequest):
    stored_pw = USERS.get(payload.email)
    if stored_pw is None or stored_pw != payload.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = encode({"email": payload.email, "role": ROLES.get(payload.email)}, SECRET, algorithm="HS256")
    return AuthenticatedUser(token=token)


@app.post("/register")
def register(payload: AuthRequest):
    if payload.email in USERS:
        raise HTTPException(status_code=409, detail="Email already registered")

    USERS[payload.email] = payload.password
    ROLES[payload.email] = Role.User
    return {"success": True}


@app.get("/current-track", response_model=CurrentTrack)
def current_track(
    response: Response,
    if_modified_since: str | None = Header(default=None, alias="If-Modified-Since"),
):
    now_local = datetime.now().astimezone()
    minute_start_local = now_local.replace(second=0, microsecond=0)
    minute_start_utc = minute_start_local.astimezone(timezone.utc)
    response.headers["Last-Modified"] = format_datetime(minute_start_utc)

    if if_modified_since:
        try:
            ims_dt = parsedate_to_datetime(if_modified_since)
            if ims_dt is not None and ims_dt.tzinfo is None:
                ims_dt = ims_dt.replace(tzinfo=timezone.utc)
            if ims_dt and ims_dt >= minute_start_utc:
                return Response(status_code=304, headers=response.headers)
        except (TypeError, ValueError, IndexError):
            pass

    return TRACKS[now_local.minute % len(TRACKS)]

@app.get("/current-host", response_model=CurrentHost)
def current_host():
    return CurrentHost(name="Peter", email="host1@radio.com")

@app.post("/wish")
def wish(payload: WishRequest, authorization: str | None = Header(default=None)):
    token = extract_bearer_token(authorization)
    decode_token(token)
    return {"success": True}

@app.post("/review")
def review(payload: ReviewRequest, authorization: str | None = Header(default=None)):
    token = extract_bearer_token(authorization)
    decoded = decode_token(token)
    if ROLES.get(payload.host_email) != Role.Host:
        raise HTTPException(status_code=400, detail="Unknown host")
    if decoded.get("email") == payload.host_email:
        raise HTTPException(status_code=400, detail="Cannot review yourself")

    REVIEWS.append(
        Review(
            review_id=next_review_id(),
            email=email,
            host_email=payload.host_email,
            rating=payload.rating,
            text=payload.text,
        )
    )
    return {"success": True}

@app.get("/get-reviews", response_model=List[Review])
def get_reviews(authorization: str | None = Header(default=None)):
    token = extract_bearer_token(authorization)
    decoded = decode_token(token)
    role = decoded.get("role")
    if role != Role.Host:
        raise HTTPException(status_code=403, detail="Host role required")
    email = decoded.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token")
    return [review for review in REVIEWS if review.host_email == email]

@app.post("/rateplaylist")
def rate_playlist(payload: RatePlaylistRequest, authorization: str | None = Header(default=None)):
    token = extract_bearer_token(authorization)
    decoded = decode_token(token)
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8080, reload=True)
