import os
import time
import hmac
import base64
import hashlib
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
import jwt
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("boveda")
logging.basicConfig(level=logging.INFO)

# ======================================================================
# CONFIGURACIÓN (variables de entorno)
#   DATABASE_URL   : conexión a PostgreSQL (como antes)
#   JWT_SECRET     : OBLIGATORIA, mínimo 32 caracteres aleatorios
#   AUTH_ENFORCED  : "false" (por defecto) = acepta clientes sin token (modo migración)
#                    "true"  = exige token en todos los endpoints protegidos
#   CORS_ORIGINS   : orígenes permitidos separados por coma (por defecto "*")
#   TOKEN_HORAS    : duración del token (por defecto 12)
#   ENABLE_DOCS    : "true" para exponer /docs (por defecto desactivado)
# ======================================================================
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "")
AUTH_ENFORCED = os.getenv("AUTH_ENFORCED", "false").lower() == "true"
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
TOKEN_HORAS = int(os.getenv("TOKEN_HORAS", "12"))
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false").lower() == "true"

if len(JWT_SECRET) < 32:
    raise RuntimeError(
        "Falta JWT_SECRET (mínimo 32 caracteres). Genera una con: "
        "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
    )

if not AUTH_ENFORCED:
    logger.warning("AUTH_ENFORCED=false: los endpoints aceptan peticiones SIN token (modo migración).")

app = FastAPI(
    title="API Bóveda de Equipos E2EE",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,  # se usa cabecera Authorization, no cookies
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ======================================================================
# BASE DE DATOS (pool de conexiones)
# ======================================================================
_pool: Optional[ThreadedConnectionPool] = None


def get_pool() -> ThreadedConnectionPool:
    global _pool
    if _pool is None:
        try:
            _pool = ThreadedConnectionPool(1, 5, DATABASE_URL, cursor_factory=RealDictCursor)
        except Exception:
            logger.exception("No se pudo crear el pool de conexiones")
            raise HTTPException(status_code=503, detail="Base de datos no disponible")
    return _pool


@contextmanager
def db_cursor():
    """Entrega un cursor; hace commit si todo sale bien y rollback si algo falla."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        # Si la conexión quedó muerta (el hosting las cierra al estar inactivas), se reemplaza
        try:
            with conn.cursor() as ping:
                ping.execute("SELECT 1")
            conn.rollback()
        except Exception:
            pool.putconn(conn, close=True)
            conn = pool.getconn()

        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
    finally:
        pool.putconn(conn)


@app.exception_handler(psycopg2.IntegrityError)
async def manejar_integridad(request: Request, exc: psycopg2.IntegrityError):
    logger.warning("Violación de integridad: %s", exc)
    return JSONResponse(status_code=400, content={"detail": "Los datos no son válidos o ya existen."})


@app.exception_handler(psycopg2.Error)
async def manejar_error_bd(request: Request, exc: psycopg2.Error):
    logger.exception("Error de base de datos")
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor."})


# ======================================================================
# CONTRASEÑAS (bcrypt; las antiguas SHA-256 se migran solas al iniciar sesión)
# ======================================================================
def _prehash(password: str) -> bytes:
    # bcrypt solo mira los primeros 72 bytes; con SHA-256 previo no se trunca nada
    return base64.b64encode(hashlib.sha256(password.encode()).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=12)).decode()


def verificar_password(password: str, almacenado: str):
    """Devuelve (es_correcta, necesita_rehash)."""
    if almacenado.startswith("$2"):
        try:
            return bcrypt.checkpw(_prehash(password), almacenado.encode()), False
        except ValueError:
            return False, False
    legacy = hashlib.sha256(password.encode()).hexdigest()  # formato anterior
    ok = hmac.compare_digest(legacy, almacenado)
    return ok, ok


_HASH_FALSO = hash_password("contraseña-de-relleno")  # iguala tiempos cuando el correo no existe


def correo_valido(email: str) -> bool:
    partes = email.split("@")
    return len(partes) == 2 and partes[0] != "" and "." in partes[1] and " " not in email and len(email) <= 254


# ======================================================================
# LÍMITE DE INTENTOS DE LOGIN (en memoria; se reinicia si el servidor se reinicia)
# ======================================================================
VENTANA_SEG = 15 * 60
MAX_FALLOS_CORREO = 5
MAX_FALLOS_IP = 20
_fallos: dict = {}


def _vigentes(clave: str) -> list:
    ahora = time.time()
    lista = [t for t in _fallos.get(clave, []) if ahora - t < VENTANA_SEG]
    if lista:
        _fallos[clave] = lista
    else:
        _fallos.pop(clave, None)
    return lista


def revisar_bloqueo(clave: str, maximo: int):
    if len(_vigentes(clave)) >= maximo:
        raise HTTPException(status_code=429, detail="Demasiados intentos fallidos. Espera 15 minutos.")


def registrar_fallo(clave: str):
    if len(_fallos) > 5000:  # evita crecer sin límite
        for k in list(_fallos):
            _vigentes(k)
    _fallos.setdefault(clave, []).append(time.time())


def ip_cliente(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "desconocida"


# ======================================================================
# AUTENTICACIÓN (JWT)
# ======================================================================
bearer = HTTPBearer(auto_error=False)


def crear_token(user: dict) -> str:
    ahora = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "iat": ahora,
        "exp": ahora + timedelta(hours=TOKEN_HORAS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _cargar_usuario(creds: Optional[HTTPAuthorizationCredentials], obligatorio: bool) -> Optional[dict]:
    if creds is None:
        if obligatorio or AUTH_ENFORCED:
            raise HTTPException(status_code=401, detail="Falta iniciar sesión.", headers={"WWW-Authenticate": "Bearer"})
        return None  # modo migración: cliente antiguo sin token
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        uid = int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sesión expirada. Vuelve a iniciar sesión.", headers={"WWW-Authenticate": "Bearer"})
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Token inválido.", headers={"WWW-Authenticate": "Bearer"})

    # Se consulta la BD para que un usuario desactivado o con rol cambiado pierda acceso de inmediato
    with db_cursor() as cur:
        cur.execute("SELECT id, nombre, rol FROM usuarios WHERE id = %s AND activo = TRUE;", (uid,))
        fila = cur.fetchone()
    if not fila:
        raise HTTPException(status_code=401, detail="Usuario inactivo o inexistente.", headers={"WWW-Authenticate": "Bearer"})
    return {"id": fila["id"], "nombre": fila["nombre"], "rol": fila.get("rol") or "tecnico"}


def usuario_actual(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> Optional[dict]:
    """Con token: usuario verificado. Sin token: None (solo si AUTH_ENFORCED=false)."""
    return _cargar_usuario(creds, obligatorio=False)


def usuario_obligatorio(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> dict:
    return _cargar_usuario(creds, obligatorio=True)


def requerir_admin(user: dict = Depends(usuario_obligatorio)) -> dict:
    if user["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Solo un administrador puede hacer esto.")
    return user


def resolver_id(user: Optional[dict], id_cliente: Optional[int], campo: str) -> int:
    """Con token manda el usuario del token; el id que envía el cliente solo se tolera si coincide."""
    if user:
        if id_cliente is not None and id_cliente != user["id"]:
            raise HTTPException(status_code=403, detail=f"'{campo}' no coincide con tu sesión.")
        return user["id"]
    if id_cliente is None:
        raise HTTPException(status_code=400, detail=f"Falta '{campo}'.")
    return id_cliente


# ======================================================================
# MODELOS
# ======================================================================
class EquipoCreate(BaseModel):
    sitio: str = Field(max_length=200)
    nombre_equipo: str = Field(max_length=200)
    tipo: str = Field(max_length=100)
    ip_direccion: str = Field(max_length=255)
    usuario_acceso: str = Field(max_length=255)
    password_cifrada: str = Field(max_length=10000)
    iv_cifrado: str = Field(max_length=100)
    creado_por: Optional[int] = None  # se ignora si hay token (se usa el del token)


class EquipoUpdate(BaseModel):
    password_cifrada_nueva: str = Field(max_length=10000)
    iv_cifrado_nuevo: str = Field(max_length=100)
    modificado_por: Optional[int] = None


class EquipoRotado(BaseModel):
    id: int
    password_cifrada: str = Field(max_length=10000)
    iv_cifrado: str = Field(max_length=100)


class HistorialRotado(BaseModel):
    id: int
    password_cifrada_anterior: str = Field(max_length=10000)
    iv_cifrado_anterior: str = Field(max_length=100)


class RotacionRequest(BaseModel):
    equipos: List[EquipoRotado]
    ignorar_ids: List[int] = []  # equipos que el cliente no pudo descifrar; quedan como están
    historial: List[HistorialRotado] = []  # versiones anteriores re-cifradas con la llave nueva
    ignorar_historial_ids: List[int] = []  # versiones que el cliente no pudo descifrar; quedan como están


class UsuarioCreate(BaseModel):
    nombre: str = Field(max_length=100)
    email: str = Field(max_length=254)
    password_personal: str = Field(min_length=8, max_length=256)


class UsuarioLogin(BaseModel):
    email: str = Field(max_length=254)
    password_personal: str = Field(max_length=256)


class CredencialPersonalCreate(BaseModel):
    usuario_id: Optional[int] = None  # se ignora si hay token
    titulo: str = Field(max_length=200)
    categoria: str = Field(default="General", max_length=100)
    url_servicio: str = Field(default="", max_length=500)
    usuario_acceso: str = Field(default="", max_length=255)
    password_cifrada: str = Field(max_length=10000)
    iv_cifrado: str = Field(max_length=100)


# ======================================================================
# SALUD
# ======================================================================
@app.get("/health")
def health():
    return {"ok": True}


# ======================================================================
# ENDPOINTS BMS
# ======================================================================
@app.post("/equipos/")
def crear_equipo(equipo: EquipoCreate, user: Optional[dict] = Depends(usuario_actual)):
    autor = resolver_id(user, equipo.creado_por, "creado_por")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO equipos (sitio, nombre_equipo, tipo, ip_direccion, usuario_acceso, password_cifrada, iv_cifrado, creado_por)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
        """, (equipo.sitio, equipo.nombre_equipo, equipo.tipo, equipo.ip_direccion,
              equipo.usuario_acceso, equipo.password_cifrada, equipo.iv_cifrado, autor))
        nuevo_id = cur.fetchone()["id"]
    return {"mensaje": "Equipo registrado con éxito", "id": nuevo_id}


@app.get("/equipos/")
def obtener_equipos(user: Optional[dict] = Depends(usuario_actual)):
    with db_cursor() as cur:
        cur.execute("""
            SELECT id, sitio, nombre_equipo, tipo, ip_direccion, usuario_acceso, password_cifrada, iv_cifrado
            FROM equipos ORDER BY sitio ASC, nombre_equipo ASC;
        """)
        return cur.fetchall()


@app.put("/equipos/{equipo_id}/password")
def actualizar_password(equipo_id: int, datos: EquipoUpdate, user: Optional[dict] = Depends(usuario_actual)):
    autor = resolver_id(user, datos.modificado_por, "modificado_por")
    with db_cursor() as cur:
        cur.execute("SELECT password_cifrada, iv_cifrado FROM equipos WHERE id = %s FOR UPDATE;", (equipo_id,))
        actual = cur.fetchone()
        if not actual:
            raise HTTPException(status_code=404, detail="Equipo no encontrado")
        cur.execute("""
            INSERT INTO historial_cambios (equipo_id, modificado_por, password_cifrada_anterior, iv_cifrado_anterior)
            VALUES (%s, %s, %s, %s);
        """, (equipo_id, autor, actual["password_cifrada"], actual["iv_cifrado"]))
        cur.execute("UPDATE equipos SET password_cifrada = %s, iv_cifrado = %s WHERE id = %s;",
                    (datos.password_cifrada_nueva, datos.iv_cifrado_nuevo, equipo_id))
    return {"mensaje": "Contraseña actualizada con éxito"}


@app.get("/equipos/{equipo_id}/historial")
def obtener_historial(equipo_id: int, user: Optional[dict] = Depends(usuario_actual)):
    with db_cursor() as cur:
        cur.execute("""
            SELECT h.id, h.fecha_cambio, u.nombre as modificado_por, h.password_cifrada_anterior, h.iv_cifrado_anterior
            FROM historial_cambios h
            JOIN usuarios u ON h.modificado_por = u.id
            WHERE h.equipo_id = %s
            ORDER BY h.fecha_cambio DESC;
        """, (equipo_id,))
        return cur.fetchall()


@app.get("/equipos/historial/todo")
def obtener_todo_el_historial(admin: dict = Depends(requerir_admin)):
    """Todo el historial cifrado (solo admin). Lo usa el cliente para re-cifrarlo al rotar la llave."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT id, equipo_id, password_cifrada_anterior, iv_cifrado_anterior
            FROM historial_cambios ORDER BY id ASC;
        """)
        return cur.fetchall()


def _comparar_ids(nombre: str, existentes: set, esperados: set):
    if esperados != existentes:
        faltan = sorted(existentes - esperados)
        sobran = sorted(esperados - existentes)
        raise HTTPException(
            status_code=409,
            detail=f"La lista de {nombre} no coincide con la actual (faltan: {faltan}, no existen: {sobran}). "
                   "Recarga la bóveda e inténtalo de nuevo; no se cambió nada.",
        )


@app.post("/equipos/rotar")
def rotar_llave_maestra(datos: RotacionRequest, admin: dict = Depends(requerir_admin)):
    """Rotación atómica: se re-cifran TODOS los equipos y TODO el historial en una sola transacción,
    o no cambia nada. La contraseña de cada equipo no cambia (solo la llave que la protege), por eso
    no se crean filas nuevas de historial. Siempre exige token de administrador."""
    ids_eq = [e.id for e in datos.equipos]
    ids_hi = [h.id for h in datos.historial]
    if len(set(ids_eq)) != len(ids_eq) or len(set(ids_hi)) != len(ids_hi):
        raise HTTPException(status_code=400, detail="Hay elementos repetidos en la lista.")
    if set(ids_eq) & set(datos.ignorar_ids) or set(ids_hi) & set(datos.ignorar_historial_ids):
        raise HTTPException(status_code=400, detail="Un elemento no puede estar rotado e ignorado a la vez.")

    with db_cursor() as cur:
        cur.execute("SELECT id FROM equipos FOR UPDATE;")  # bloquea todo mientras se rota
        eq_existentes = {fila["id"] for fila in cur.fetchall()}
        cur.execute("SELECT id FROM historial_cambios FOR UPDATE;")
        hi_existentes = {fila["id"] for fila in cur.fetchall()}

        _comparar_ids("equipos", eq_existentes, set(ids_eq) | set(datos.ignorar_ids))
        _comparar_ids("historial", hi_existentes, set(ids_hi) | set(datos.ignorar_historial_ids))

        for e in datos.equipos:
            cur.execute("UPDATE equipos SET password_cifrada = %s, iv_cifrado = %s WHERE id = %s;",
                        (e.password_cifrada, e.iv_cifrado, e.id))
        for h in datos.historial:
            cur.execute("""
                UPDATE historial_cambios SET password_cifrada_anterior = %s, iv_cifrado_anterior = %s
                WHERE id = %s;
            """, (h.password_cifrada_anterior, h.iv_cifrado_anterior, h.id))

    logger.info("Rotación de llave maestra por usuario %s (equipos: %d, historial: %d, ignorados: %d/%d)",
                admin["id"], len(datos.equipos), len(datos.historial),
                len(datos.ignorar_ids), len(datos.ignorar_historial_ids))
    return {
        "mensaje": "Rotación completa",
        "rotados": len(datos.equipos),
        "historial_rotado": len(datos.historial),
        "ignorados": len(datos.ignorar_ids),
        "historial_ignorado": len(datos.ignorar_historial_ids),
    }


# ======================================================================
# USUARIOS Y LOGIN
# ======================================================================
@app.post("/usuarios/")
def crear_usuario(usuario: UsuarioCreate, user: Optional[dict] = Depends(usuario_actual)):
    # Con token: solo administradores. Sin token: solo se tolera en modo migración.
    if user is not None and user["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Solo un administrador puede registrar compañeros.")
    if user is None:
        logger.warning("Registro de usuario SIN token (modo migración)")

    email = usuario.email.strip().lower()
    if not correo_valido(email):
        raise HTTPException(status_code=400, detail="Correo electrónico no válido.")

    with db_cursor() as cur:
        cur.execute("SELECT 1 FROM usuarios WHERE LOWER(email) = %s;", (email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="El correo ya existe o hubo un error")
        cur.execute("""
            INSERT INTO usuarios (nombre, email, password_hash, rol)
            VALUES (%s, %s, %s, 'tecnico') RETURNING id;
        """, (usuario.nombre.strip(), email, hash_password(usuario.password_personal)))
        nuevo_id = cur.fetchone()["id"]
    return {"mensaje": f"Usuario {usuario.nombre} registrado", "id": nuevo_id}


@app.post("/login")
def login(usuario: UsuarioLogin, request: Request):
    email = usuario.email.strip().lower()
    clave_correo, clave_ip = f"c:{email}", f"i:{ip_cliente(request)}"
    revisar_bloqueo(clave_correo, MAX_FALLOS_CORREO)
    revisar_bloqueo(clave_ip, MAX_FALLOS_IP)

    with db_cursor() as cur:
        cur.execute("SELECT id, nombre, rol, password_hash FROM usuarios WHERE LOWER(email) = %s AND activo = TRUE;", (email,))
        fila = cur.fetchone()

        if fila:
            ok, rehash = verificar_password(usuario.password_personal, fila["password_hash"])
        else:
            verificar_password(usuario.password_personal, _HASH_FALSO)  # mismo tiempo de respuesta
            ok, rehash = False, False

        if not ok:
            registrar_fallo(clave_correo)
            registrar_fallo(clave_ip)
            raise HTTPException(status_code=401, detail="Correo o contraseña personal incorrectos")

        if rehash:  # migra el hash SHA-256 antiguo a bcrypt de forma transparente
            try:
                cur.execute("UPDATE usuarios SET password_hash = %s WHERE id = %s;",
                            (hash_password(usuario.password_personal), fila["id"]))
            except psycopg2.Error:
                # Que la migración falle no debe impedir entrar (se reintenta en el próximo login)
                logger.warning("No se pudo migrar el hash del usuario %s. Ejecuta: "
                               "ALTER TABLE usuarios ALTER COLUMN password_hash TYPE TEXT;", fila["id"])

    _fallos.pop(clave_correo, None)
    rol = fila.get("rol") or "tecnico"
    return {
        "id": fila["id"],
        "nombre": fila["nombre"],
        "rol": rol,
        "token": crear_token(fila),
        "token_type": "bearer",
        "expira_en": TOKEN_HORAS * 3600,
    }


# ======================================================================
# BÓVEDA PERSONAL
# ======================================================================
@app.post("/personales/")
def crear_credencial_personal(item: CredencialPersonalCreate, user: Optional[dict] = Depends(usuario_actual)):
    dueno = resolver_id(user, item.usuario_id, "usuario_id")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO equipos_personales (usuario_id, titulo, categoria, url_servicio, usuario_acceso, password_cifrada, iv_cifrado)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;
        """, (dueno, item.titulo, item.categoria, item.url_servicio, item.usuario_acceso,
              item.password_cifrada, item.iv_cifrado))
        nuevo_id = cur.fetchone()["id"]
    return {"mensaje": "Credencial guardada", "id": nuevo_id}


@app.get("/personales/{usuario_id}")
def obtener_credenciales_personales(usuario_id: int, user: Optional[dict] = Depends(usuario_actual)):
    dueno = resolver_id(user, usuario_id, "usuario_id")  # con token solo puedes ver las tuyas
    with db_cursor() as cur:
        cur.execute("""
            SELECT id, titulo, categoria, url_servicio, usuario_acceso, password_cifrada, iv_cifrado
            FROM equipos_personales
            WHERE usuario_id = %s
            ORDER BY categoria ASC, titulo ASC;
        """, (dueno,))
        return cur.fetchall()


@app.delete("/personales/{item_id}")
def eliminar_credencial_personal(item_id: int, user: Optional[dict] = Depends(usuario_actual)):
    with db_cursor() as cur:
        if user:
            cur.execute("DELETE FROM equipos_personales WHERE id = %s AND usuario_id = %s;", (item_id, user["id"]))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Credencial no encontrada")
        else:
            logger.warning("Borrado de credencial personal SIN token (modo migración)")
            cur.execute("DELETE FROM equipos_personales WHERE id = %s;", (item_id,))
    return {"mensaje": "Credencial eliminada"}
