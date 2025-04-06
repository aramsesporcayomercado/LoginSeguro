from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import mysql.connector
import bcrypt
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from Config import MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB

app = FastAPI()

# Configuración de CORS
origins = [
    "http://localhost:3000",
    "https://localhost:3000",
    "http://127.0.0.1:8000",
    "http://192.168.100.6:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conectar a la base de datos MySQL
conn = mysql.connector.connect(
    host=MYSQL_HOST,
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    database=MYSQL_DB
)

# Crear un cursor
cursor = conn.cursor()

# Insertar usuario y contraseña si no existen
try:
    cursor.execute('SELECT * FROM usuarios WHERE username = %s', ('arath',))
    if not cursor.fetchone():
        password_str = "Marron5"
        password_bytes = password_str.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        # Almacena el hash como string para evitar problemas de conversión luego
        cursor.execute(
            'INSERT INTO usuarios (username, password) VALUES (%s, %s)',
            ('arath', hashed_password.decode('utf-8'))
        )
        conn.commit()
except mysql.connector.Error as err:
    print(f"Error al insertar usuario: {err}")

# Modelo para el login
class LoginData(BaseModel):
    username: str
    password: str

# Endpoint de login que recibe JSON
@app.post("/login")
async def login(login_data: LoginData):
    username = login_data.username
    password = login_data.password

    try:
        input_password = password.encode('utf-8')  # Convertir la contraseña a bytes
        cursor.execute('SELECT password FROM usuarios WHERE username = %s', (username,))
        stored_hash = cursor.fetchone()

        if stored_hash:
            # stored_hash[0] es una cadena, conviértela a bytes para la comparación
            stored_hash_bytes = stored_hash[0].encode('utf-8')
            if bcrypt.checkpw(input_password, stored_hash_bytes):
                return JSONResponse(content={"message": "Login exitoso"}, status_code=200)
        
        return JSONResponse(content={"message": "Usuario o contraseña incorrectos"}, status_code=401)
    except mysql.connector.Error as err:
        return JSONResponse(content={"message": f"Error al verificar credenciales: {err}"}, status_code=500)

