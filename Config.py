import os

SECRET_KEY = os.getenv("SECRET_KEY",  "zerotwo")
ALGORITHM = "HS256"


# Configuración de la base de datos
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")  # Host de la base de datos
MYSQL_USER = os.getenv("MYSQL_USER", "root")       # Usuario de la base de datos
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")    # Contraseña de la base de datos (vacía)
MYSQL_DB = os.getenv("MYSQL_DB", "login")          # Nombre de la base de datos
