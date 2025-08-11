from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List
from pydantic import BaseModel
import jwt
import os

# === Создание приложения ===
app = FastAPI()

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === HTML шаблоны ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# === JWT настройки ===
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# === Пароли ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# === База пользователей ===
fake_users = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("1535"),
        "history": [],
        "reports": []
    },
    "#1535": {
        "username": "#1535",
        "hashed_password": pwd_context.hash("12345"),
        "history": [],
        "reports": []
    }
}

# === Глобальная база ников и отчётов ===
taken_nicks = set()
global_history = []
global_reports = []

# === Утилиты ===
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user = fake_users.get(username)
    if user and verify_password(password, user["hashed_password"]):
        return user
    return None

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username not in fake_users:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return fake_users[username]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# === Модели ===
class NicknameRequest(BaseModel):
    nicknames: List[str]

# === Роуты ===
@app.get("/", response_class=HTMLResponse)
def get_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/check")
def check_nicknames(data: NicknameRequest, user=Depends(get_current_user)):
    results = []
    for nick in data.nicknames:
        if nick in taken_nicks:
            status = "Ник занят"
        else:
            status = "Не найдено"
            taken_nicks.add(nick)
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "nickname": nick,
            "status": status,
            "user": user["username"]
        }
        user["history"].append(entry)
        global_history.append(entry)
        results.append({"nickname": nick, "status": status})
    return {"results": results}

@app.get("/history")
def get_history(user=Depends(get_current_user)):
    if user["username"] == "admin":
        sorted_history = sorted(global_history, key=lambda x: x["time"], reverse=True)
        return [
            f"{item['time']} — {item['user']} — {item['nickname']} — {item['status']}"
            for item in sorted_history
        ]
    else:
        return [
            f"{item['time']} — {item['nickname']} — {item['status']}"
            for item in sorted(user["history"], key=lambda x: x["time"], reverse=True)
        ]

# === Форма отчётов ===
@app.get("/reports", response_class=HTMLResponse)
def get_report_form(request: Request, user=Depends(get_current_user)):
    return templates.TemplateResponse("report_form.html", {"request": request, "user": user})

@app.post("/report", response_class=HTMLResponse)
def send_report(
    request: Request,
    date: str = Form(...),
    active: str = Form(...),
    new: str = Form(...),
    throws: str = Form(...),
    offers: str = Form(...),
    agrees: str = Form(...),
    leads: str = Form(...),
    deposits: str = Form(...),
    user=Depends(get_current_user)
):
    report_entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "date": date,
        "active": active,
        "new": new,
        "throws": throws,
        "offers": offers,
        "agrees": agrees,
        "leads": leads,
        "deposits": deposits,
        "manager": user["username"]
    }
    user["reports"].append(report_entry)
    global_reports.append(report_entry)
    return templates.TemplateResponse("report_success.html", {"request": request, "report": report_entry})

@app.get("/all-reports", response_class=HTMLResponse)
def get_all_reports(request: Request, user=Depends(get_current_user)):
    if user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Нет доступа")
    return templates.TemplateResponse("all_reports.html", {"request": request, "reports": global_reports})
