import os
import psycopg2
import hashlib # NUEVA IMPORTACIÓN
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware # NUEVA IMPORTACIÓN
from pydantic import BaseModel
from dotenv import load_dotenv

# Cargar la URL desde el archivo .env
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI(title="API Bóveda de Equipos E2EE")
# NUEVO: Permitir que la web se conecte a la API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción limitaremos esto a la URL de tu web
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        # Esto imprimirá el error real en tu terminal de VS Code
        print(f"\n--- DETALLE DEL ERROR DE BASE DE DATOS ---\n{e}\n------------------------------------------\n")
        raise HTTPException(status_code=500, detail="Error conectando a la base de datos")

# Modelos Pydantic (Estructura de datos que recibe la API)
class EquipoCreate(BaseModel):
    sitio: str
    nombre_equipo: str
    tipo: str
    ip_direccion: str
    usuario_acceso: str
    password_cifrada: str  # Texto encriptado desde Android/Web
    iv_cifrado: str        # Vector de inicialización
    creado_por: int        # ID del usuario que registra el equipo

@app.post("/equipos/")
def crear_equipo(equipo: EquipoCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            INSERT INTO equipos (sitio, nombre_equipo, tipo, ip_direccion, usuario_acceso, password_cifrada, iv_cifrado, creado_por)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
        """
        cursor.execute(query, (
            equipo.sitio, equipo.nombre_equipo, equipo.tipo, equipo.ip_direccion, 
            equipo.usuario_acceso, equipo.password_cifrada, equipo.iv_cifrado, equipo.creado_por
        ))
        nuevo_id = cursor.fetchone()['id']
        conn.commit()
        return {"mensaje": "Equipo registrado con éxito", "id": nuevo_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.get("/equipos/")
def obtener_equipos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, sitio, nombre_equipo, tipo, ip_direccion, usuario_acceso, password_cifrada, iv_cifrado FROM equipos ORDER BY sitio ASC, nombre_equipo ASC;")
    equipos = cursor.fetchall()
    cursor.close()
    conn.close()
    return equipos
# --- NUEVOS MODELOS Y ENDPOINTS PARA HISTORIAL Y ACTUALIZACIÓN ---

class EquipoUpdate(BaseModel):
    password_cifrada_nueva: str
    iv_cifrado_nuevo: str
    modificado_por: int  # ID del usuario que hace el cambio

@app.put("/equipos/{equipo_id}/password")
def actualizar_password(equipo_id: int, update_data: EquipoUpdate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 1. Obtener la contraseña actual antes de borrarla
        cursor.execute("SELECT password_cifrada, iv_cifrado FROM equipos WHERE id = %s;", (equipo_id,))
        equipo_actual = cursor.fetchone()

        if not equipo_actual:
            raise HTTPException(status_code=404, detail="Equipo no encontrado")

        # 2. Guardar la versión anterior en la bitácora de historial
        cursor.execute("""
            INSERT INTO historial_cambios (equipo_id, modificado_por, password_cifrada_anterior, iv_cifrado_anterior)
            VALUES (%s, %s, %s, %s);
        """, (equipo_id, update_data.modificado_por, equipo_actual['password_cifrada'], equipo_actual['iv_cifrado']))

        # 3. Sobreescribir con la nueva contraseña en la tabla principal
        cursor.execute("""
            UPDATE equipos 
            SET password_cifrada = %s, iv_cifrado = %s 
            WHERE id = %s;
        """, (update_data.password_cifrada_nueva, update_data.iv_cifrado_nuevo, equipo_id))

        conn.commit()
        return {"mensaje": "Contraseña actualizada y versión anterior respaldada con éxito"}
    except Exception as e:
        conn.rollback()
        print(f"\n--- ERROR EN PUT ---\n{e}\n--------------------\n")
        raise HTTPException(status_code=500, detail="Error al actualizar la contraseña")
    finally:
        cursor.close()
        conn.close()

@app.get("/equipos/{equipo_id}/historial")
def obtener_historial(equipo_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Hacemos un JOIN para que nos devuelva el nombre de tu compañero, no solo su número de ID
    cursor.execute("""
        SELECT h.id, h.fecha_cambio, u.nombre as modificado_por, h.password_cifrada_anterior, h.iv_cifrado_anterior 
        FROM historial_cambios h
        JOIN usuarios u ON h.modificado_por = u.id
        WHERE h.equipo_id = %s
        ORDER BY h.fecha_cambio DESC;
    """, (equipo_id,))
    historial = cursor.fetchall()
    cursor.close()
    conn.close()
    return historial
# --- NUEVOS MODELOS Y ENDPOINTS DE IDENTIDAD ---

class UsuarioCreate(BaseModel):
    nombre: str
    email: str
    password_personal: str

class UsuarioLogin(BaseModel):
    email: str
    password_personal: str

@app.post("/usuarios/")
def crear_usuario(usuario: UsuarioCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Convertimos la contraseña personal en un Hash seguro (unidireccional)
        hash_pw = hashlib.sha256(usuario.password_personal.encode()).hexdigest()
        
        cursor.execute("""
            INSERT INTO usuarios (nombre, email, password_hash)
            VALUES (%s, %s, %s) RETURNING id;
        """, (usuario.nombre, usuario.email, hash_pw))
        
        nuevo_id = cursor.fetchone()['id']
        conn.commit()
        return {"mensaje": f"Usuario {usuario.nombre} registrado con éxito", "id": nuevo_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="El correo ya existe o hubo un error en la base de datos")
    finally:
        cursor.close()
        conn.close()

@app.post("/login")
def login(usuario: UsuarioLogin):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Repetimos el Hash para compararlo con el que está en la base de datos
        hash_pw = hashlib.sha256(usuario.password_personal.encode()).hexdigest()
        
        cursor.execute("SELECT id, nombre FROM usuarios WHERE email = %s AND password_hash = %s AND activo = TRUE;", 
                       (usuario.email, hash_pw))
        user_db = cursor.fetchone()
        
        if not user_db:
            raise HTTPException(status_code=401, detail="Correo o contraseña personal incorrectos")
            
        # Si coincide, le devolvemos la identidad a la página web
        return {"id": user_db['id'], "nombre": user_db['nombre']}
    finally:
        cursor.close()
        conn.close()