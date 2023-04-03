from datetime import datetime, timedelta
from typing import Annotated, Union
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    status,
    Request,
    Form,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from data import crud, models, schemas
from data.database import SessionLocal, engine
from sqlalchemy.orm import Session
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import os

SECRET_KEY = os.environ.get("SWA_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
messages = []


class Message:
    def __init__(self, username: str, message: str, timestamp: str):
        self.username = username
        self.message = message
        self.timestamp = timestamp


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class UserSignUpData(BaseModel):
    username: str
    password: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# Define allowed origins
origins = [
    "*",
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:8000/protected/",
    "http://localhost:8000/login/",
]

# Add middleware for CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")
models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return schemas.User(**user_dict)


def authenticate_user(db, username: str, password: str):
    user = crud.get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_token(request: Request):
    db = SessionLocal()
    access_token = request.cookies.get("access_token")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    db = SessionLocal()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[schemas.User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/", response_class=HTMLResponse)
async def root_page(request: Request):
    return templates.TemplateResponse("m.html", {"request": request})


@app.post("/login")
def login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db),
):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse("failure.html", {"request": request})
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        response = templates.TemplateResponse(
            "dashboard2.html",
            {
                "request": request,
                "full_name": user.full_name,
                "email": user.email,
                "username": user.username,
            },
        )
        response.set_cookie(key="access_token", value=access_token)
        return response


@app.get("/signup", response_class=HTMLResponse)
async def root_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})


@app.post(
    "/signup-apply",
)
async def signup(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        fullname: str = Form(...),
        email: str = Form(...),
        db: Session = Depends(get_db),
):
    all_users = crud.get_all_usernames(db)
    if username not in all_users:
        user = schemas.User(
            username=username,
            full_name=fullname,
            hashed_password=get_password_hash(password),
            email=email,
            disabled=False,
        )
        crud.create_user(db, user)
        return templates.TemplateResponse("m.html", {"request": request})
    else:
        return {"message": "username already exist"}


@app.post("/token", response_model=Token)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/chat/", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse(
        "chat.html", {"request": request, "messages": messages}
    )


@app.post("/post_message/")
async def post_message(request: Request, message: str = Form(...)):
    user = get_user_by_token(request)
    new_message = Message(
        username=user.username,
        message=message,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    messages.append(new_message)
    return {"messages": messages}


@app.get("/edit-info/")
async def edit_info(request: Request):
    user = get_user_by_token(request)
    return templates.TemplateResponse(
        "info-edit.html",
        {"request": request, "full_name": user.full_name, "email": user.email},
    )


@app.get("/edit-pass/")
async def edit_info(request: Request):
    return templates.TemplateResponse("pass-edit.html", {"request": request})


@app.post("/edit-pass-save/")
async def edit_info_save(
        request: Request, password: str = Form(...), db: Session = Depends(get_db)
):
    user = get_user_by_token(request)
    crud.change_password_by_username(db, user.username, get_password_hash(password))
    return templates.TemplateResponse("m.html", {"request": request})


@app.post("/edit-info-save/")
async def edit_info_save(
        request: Request,
        email: str = Form(...),
        full_name: str = Form(...),
        db: Session = Depends(get_db),
):
    user = get_user_by_token(request)
    crud.change_full_name_and_email_by_username(db, user.username, full_name, email)
    return templates.TemplateResponse("m.html", {"request": request})


@app.get("/view-users/")
def view_others(request: Request, db: Session = Depends(get_db)):
    users = crud.get_all_users(db)
    return templates.TemplateResponse("view-others.html", {"request": request, "users": users})

