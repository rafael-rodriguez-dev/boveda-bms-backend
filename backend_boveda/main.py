import os
import psycopg2
import hashlib
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI(title="API Bóveda de Equipos E2EE")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"\n--- DETALLE DEL ERROR DE BASE DE DATOS ---\n{e}\n------------------------------------------\n")
        raise HTTPException(status_code=500, detail="Error conectando a la base de datos")

# --- MODELOS BMS ---
class EquipoCreate(BaseModel):
    sitio: str
    nombre_equipo: str
    tipo: str
    ip_direccion: str
    usuario_acceso: str
    password_cifrada: str
    iv_cifrado: str
    creado_por: int

class EquipoUpdate(BaseModel):
    password_cifrada_nueva: str
    iv_cifrado_nuevo: str
    modificado_por: int

class UsuarioCreate(BaseModel):
    nombre: str
    email: str
    password_personal: str

class UsuarioLogin(BaseModel):
    email: str
    password_personal: str

# --- MODELOS BÓVEDA PERSONAL ---
class CredencialPersonalCreate(BaseModel):
    usuario_id: int
    titulo: str
    categoria: str = "General"
    url_servicio: str = ""
    usuario_acceso: str = ""
    password_cifrada: str
    iv_cifrado: str

# --- ENDPOINTS BMS ---
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

@app.put("/equipos/{equipo_id}/password")
def actualizar_password(equipo_id: int, update_data: EquipoUpdate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_cifrada, iv_cifrado FROM equipos WHERE id = %s;", (equipo_id,))
        equipo_actual = cursor.fetchone()
        if not equipo_actual:
            raise HTTPException(status_code=404, detail="Equipo no encontrado")

        cursor.execute("""
            INSERT INTO historial_cambios (equipo_id, modificado_por, password_cifrada_anterior, iv_cifrado_anterior)
            VALUES (%s, %s, %s, %s);
        """, (equipo_id, update_data.modificado_por, equipo_actual['password_cifrada'], equipo_actual['iv_cifrado']))

        cursor.execute("""
            UPDATE equipos 
            SET password_cifrada = %s, iv_cifrado = %s 
            WHERE id = %s;
        """, (update_data.password_cifrada_nueva, update_data.iv_cifrado_nuevo, equipo_id))

        conn.commit()
        return {"mensaje": "Contraseña actualizada con éxito"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail="Error al actualizar la contraseña")
    finally:
        cursor.close()
        conn.close()

@app.get("/equipos/{equipo_id}/historial")
def obtener_historial(equipo_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
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

# --- ENDPOINTS USUARIOS Y LOGIN ---
@app.post("/usuarios/")
def crear_usuario(usuario: UsuarioCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        hash_pw = hashlib.sha256(usuario.password_personal.encode()).hexdigest()
        # Se guarda por defecto con rol 'tecnico'
        cursor.execute("""
            INSERT INTO usuarios (nombre, email, password_hash, rol)
            VALUES (%s, %s, %s, 'tecnico') RETURNING id;
        """, (usuario.nombre, usuario.email, hash_pw))
        nuevo_id = cursor.fetchone()['id']
        conn.commit()
        return {"mensaje": f"Usuario {usuario.nombre} registrado", "id": nuevo_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="El correo ya existe o hubo un error")
    finally:
        cursor.close()
        conn.close()

@app.post("/login")
def login(usuario: UsuarioLogin):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        hash_pw = hashlib.sha256(usuario.password_personal.encode()).hexdigest()
        # AHORA PEDIMOS EL ROL TAMBIÉN
        cursor.execute("SELECT id, nombre, rol FROM usuarios WHERE email = %s AND password_hash = %s AND activo = TRUE;", 
                       (usuario.email, hash_pw))
        user_db = cursor.fetchone()
        
        if not user_db:
            raise HTTPException(status_code=401, detail="Correo o contraseña personal incorrectos")
            
        return {"id": user_db['id'], "nombre": user_db['nombre'], "rol": user_db.get('rol', 'tecnico')}
    finally:
        cursor.close()
        conn.close()

# --- ENDPOINTS BÓVEDA PERSONAL ---
@app.post("/personales/")
def crear_credencial_personal(item: CredencialPersonalCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            INSERT INTO equipos_personales (usuario_id, titulo, categoria, url_servicio, usuario_acceso, password_cifrada, iv_cifrado)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;
        """
        cursor.execute(query, (
            item.usuario_id, item.titulo, item.categoria,
            item.url_servicio, item.usuario_acceso, item.password_cifrada, item.iv_cifrado
        ))
        nuevo_id = cursor.fetchone()['id']
        conn.commit()
        return {"mensaje": "Credencial guardada", "id": nuevo_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        conn.close()

@app.get("/personales/{usuario_id}")
def obtener_credenciales_personales(usuario_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            SELECT id, titulo, categoria, url_servicio, usuario_acceso, password_cifrada, iv_cifrado 
            FROM equipos_personales 
            WHERE usuario_id = %s 
            ORDER BY categoria ASC, titulo ASC;
        """
        cursor.execute(query, (usuario_id,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

@app.delete("/personales/{item_id}")
def eliminar_credencial_personal(item_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM equipos_personales WHERE id = %s;", (item_id,))
        conn.commit()
        return {"mensaje": "Credencial eliminada"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cursor.close()
        conn.close()