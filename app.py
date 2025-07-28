from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import SQLModel, Field, Session, create_engine, select
from typing import Optional, List
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.hash import bcrypt

SECRET_KEY = "CHANGE_ME"
ALGORITHM = "HS256"
TOKEN_HOURS = 48

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    group: str = Field(default="user")

class UserCreate(SQLModel):
    username: str
    password: str
    group: Optional[str] = "user"

class UserRead(SQLModel):
    id: int
    username: str
    group: str

class UserUpdate(SQLModel):
    username: Optional[str] = None
    password: Optional[str] = None
    group: Optional[str] = None

class Advertisement(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    description: Optional[str] = None
    price: float
    author_id: int
    author: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AdCreate(SQLModel):
    title: str
    description: Optional[str] = None
    price: float

class AdRead(SQLModel):
    id: int
    title: str
    description: Optional[str]
    price: float
    author_id: int
    author: str
    created_at: datetime

class AdUpdate(SQLModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None

app = FastAPI()
engine = create_engine("sqlite:///ads.db")
SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as s:
        yield s

security = HTTPBearer(auto_error=False)

def create_token(user_id: int, group: str) -> str:
    payload = {"sub": str(user_id), "grp": group, "exp": datetime.utcnow() + timedelta(hours=TOKEN_HOURS)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_optional(
    creds: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session),
):
    if creds is None:
        return None
    token = creds.credentials
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401)
    user = session.get(User, int(data.get("sub", 0)))
    if not user:
        raise HTTPException(status_code=401)
    return user

def get_current_user(
    user = Depends(get_current_user_optional)
):
    if user is None:
        raise HTTPException(status_code=401)
    return user

def is_admin(user: User) -> bool:
    return user.group == "admin"

def ensure_self_or_admin(current: User, target_id: int):
    if current.id != target_id and not is_admin(current):
        raise HTTPException(status_code=403)

def ensure_owner_or_admin(current: User, ad: Advertisement):
    if current.id != ad.author_id and not is_admin(current):
        raise HTTPException(status_code=403)

@app.post("/login")
def login(data: UserCreate, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == data.username)).first()
    if not user or not bcrypt.verify(data.password, user.password_hash):
        raise HTTPException(status_code=401)
    return {"token": create_token(user.id, user.group)}

@app.post("/user", response_model=UserRead, status_code=201)
def create_user(u: UserCreate, session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.username == u.username)).first():
        raise HTTPException(status_code=400, detail="username taken")
    hashed = bcrypt.hash(u.password)
    db_u = User(username=u.username, password_hash=hashed, group=u.group or "user")
    session.add(db_u)
    session.commit()
    session.refresh(db_u)
    return db_u

@app.get("/user/{user_id}", response_model=UserRead)
def get_user(user_id: int, session: Session = Depends(get_session)):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404)
    return u

@app.get("/user", response_model=List[UserRead])
def list_users(session: Session = Depends(get_session), current: User = Depends(get_current_user)):
    if not is_admin(current):
        raise HTTPException(status_code=403)
    return session.exec(select(User)).all()

@app.patch("/user/{user_id}", response_model=UserRead)
def update_user(user_id: int, payload: UserUpdate, session: Session = Depends(get_session), current: User = Depends(get_current_user)):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404)
    ensure_self_or_admin(current, user_id)
    data = payload.dict(exclude_unset=True)
    if "password" in data:
        data["password_hash"] = bcrypt.hash(data.pop("password"))
    for k, v in data.items():
        setattr(u, k, v)
    session.add(u)
    session.commit()
    session.refresh(u)
    return u

@app.delete("/user/{user_id}", status_code=204)
def delete_user(user_id: int, session: Session = Depends(get_session), current: User = Depends(get_current_user)):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404)
    ensure_self_or_admin(current, user_id)
    session.delete(u)
    session.commit()

@app.post("/advertisement", response_model=AdRead, status_code=201)
def create_ad(ad: AdCreate, session: Session = Depends(get_session), current: User = Depends(get_current_user)):
    db_ad = Advertisement(**ad.dict(), author_id=current.id, author=current.username)
    session.add(db_ad)
    session.commit()
    session.refresh(db_ad)
    return db_ad

@app.patch("/advertisement/{ad_id}", response_model=AdRead)
def update_ad(ad_id: int, upd: AdUpdate, session: Session = Depends(get_session), current: User = Depends(get_current_user)):
    ad = session.get(Advertisement, ad_id)
    if not ad:
        raise HTTPException(status_code=404)
    ensure_owner_or_admin(current, ad)
    for k, v in upd.dict(exclude_unset=True).items():
        setattr(ad, k, v)
    session.add(ad)
    session.commit()
    session.refresh(ad)
    return ad

@app.delete("/advertisement/{ad_id}", status_code=204)
def delete_ad(ad_id: int, session: Session = Depends(get_session), current: User = Depends(get_current_user)):
    ad = session.get(Advertisement, ad_id)
    if not ad:
        raise HTTPException(status_code=404)
    ensure_owner_or_admin(current, ad)
    session.delete(ad)
    session.commit()

@app.get("/advertisement/{ad_id}", response_model=AdRead)
def get_ad(ad_id: int, session: Session = Depends(get_session)):
    ad = session.get(Advertisement, ad_id)
    if not ad:
        raise HTTPException(status_code=404)
    return ad

@app.get("/advertisement", response_model=List[AdRead])
def search_ads(
    title: Optional[str] = None,
    author: Optional[str] = None,
    price_min: Optional[float] = None,
    price_max: Optional[float] = None,
    session: Session = Depends(get_session),
):
    stmt = select(Advertisement)
    if title:
        stmt = stmt.where(Advertisement.title.contains(title))
    if author:
        stmt = stmt.where(Advertisement.author == author)
    if price_min is not None:
        stmt = stmt.where(Advertisement.price >= price_min)
    if price_max is not None:
        stmt = stmt.where(Advertisement.price <= price_max)
    return session.exec(stmt).all()
