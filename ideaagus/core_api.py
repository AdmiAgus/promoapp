# -*- coding: utf-8 -*-
import sys
import asyncio


# Fix para Windows: Playwright requiere ProactorEventLoop
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.responses import JSONResponse, PlainTextResponse
from anses_core import process_input, scrape_anses
from nosis import nosis_lookup
from nosis2 import nosis2_lookup
from nosis3 import nosis3_lookup
# from aportes import aportes_lookup  # TEMPORAL: archivo no existe
from arcaprueba import arca_lookup
from sss import sss_lookup, formatear_resultado_whatsapp
from mono_pagos import mono_pagos_lookup, formatear_resultado_whatsapp as formatear_mono_pagos
from monotras import monotras_lookup
from blanco import blanco_lookup
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Importar sistema de cache
from cache import (
    get_from_cache, save_to_cache, delete_from_cache, 
    delete_all_for_cuil, cleanup_expired_cache, get_cache_stats,
    normalize_cuil_dni
)

import logging
import time
import os
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import httpx

from collections import defaultdict
from dotenv import load_dotenv

# Cargar variables de entorno desde archivo .env
load_dotenv()

HC_CORE = os.getenv("HEALTHCHECK_URL")

# ----------------- Funciones helper para cache -----------------

def _codem_should_cache(resultado: str) -> bool:
    no_cache_prefixes = ("Error:", "Error inesperado:")
    no_cache_substrings = ("CAPTCHA",)
    return not any(resultado.startswith(p) for p in no_cache_prefixes) and \
           not any(s in resultado for s in no_cache_substrings)

def _sss_should_cache(resultado: dict) -> bool:
    if resultado.get('ok'):
        return True
    error = resultado.get('error', '')
    no_cache = ["WEB_CAIDA", "WEB_CAIDA_PADRON", "No se pudo obtener un CUIL válido",
                "Error Nosis", "Formato inválido", "No se pudo determinar"]
    return not any(e in error for e in no_cache)

def _arca_should_cache(result: dict) -> bool:
    if result.get('ok'):
        return True
    error = str(result.get('error', '')).lower()
    no_cache = ["timeout", "web_caida", "error inesperado", "playwright", "connection", "conexi"]
    return not any(e in error for e in no_cache)

def _mono_pagos_should_cache(resultado: dict) -> bool:
    if resultado.get('ok'):
        return True
    cacheable_errors = {"No se encontraron datos para este CUIL"}
    return resultado.get('error', '') in cacheable_errors

def _monotras_should_cache(resultado: dict) -> bool:
    if resultado.get('ok'):
        return True
    cacheable_errors = {"No se encontraron datos para este CUIL"}
    return resultado.get('error', '') in cacheable_errors

# ----------------- Configuración de logging -----------------

logger = logging.getLogger("bot_requests")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# ----------------- Bloqueo de IPs -----------------

ip_banlist = {}
IP_BAN_DURATION = timedelta(minutes=30)

def is_ip_banned(ip: str):
    expiration = ip_banlist.get(ip)
    if expiration and expiration > datetime.now():
        return True
    elif expiration:
        del ip_banlist[ip]
    return False

def ban_ip(ip: str):
    ip_banlist[ip] = datetime.now() + IP_BAN_DURATION
    logger.warning(f"[BLOQUEO] IP bloqueada temporalmente: {ip}")

# ----------------- Función para extraer IP cliente -----------------

def get_remote_address_filtered(request: Request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else "127.0.0.1"
    if ip in ["127.0.0.1", "::1", "localhost"]:
        return "localhost-exempt"
    return ip

# ----------------- Inicialización de FastAPI -----------------

limiter = Limiter(key_func=get_remote_address_filtered)
app = FastAPI()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ----------------- Middleware de log con IP -----------------

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    timestamp = datetime.now().strftime("%H:%M:%S")
    client_ip = get_remote_address_filtered(request)

    if is_ip_banned(client_ip):
        logger.warning(f"[{timestamp}] ✗ Request bloqueada por IP ({client_ip})")
        return JSONResponse(status_code=403, content={"error": "Acceso denegado"})

    response = await call_next(request)
    process_time = time.time() - start_time

    suspicious_patterns = [
        ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".py", ".sh",
        ".htm", ".html", ".xml", ".json", ".bak", ".old", ".zip",
        "wp-", "wordpress", "phpmyadmin", "joomla", "drupal", "magento",
        ".env", ".git", ".svn", ".hg", "config", ".ini", ".conf",
        "eval", "exec", "shell", "cmd", "system", "passthru",
        "sql", "union", "select", "insert", "update", "delete", "drop",
        "../", "..\\", "..%2f", "..%5c",
        "clientapi", "ipip", "netecho", "xmlrpc",
        "wp-admin", "console", "manager", "setup", "install",
        "backup", "test", "demo", "default", "index.htm",
        ".action", ".do", ".cfm", ".axd"
    ]
    
    path_lower = request.url.path.lower()
    # Excluir rutas de auth del chequeo de patrones sospechosos
    is_auth_route = path_lower.startswith("/auth/")
    is_promotores = path_lower.startswith("/promotores")
    is_suspicious = not is_auth_route and not is_promotores and any(pattern in path_lower for pattern in suspicious_patterns)
    
    if is_suspicious and response.status_code in [403, 404, 405]:
        logger.warning(f"[{timestamp}] 🚫 Intento malicioso bloqueado: {client_ip} -> {request.url.path}")
        ban_ip(client_ip)
    
    if not is_suspicious and request.url.path not in ["/", "/help"]:
        endpoint = request.url.path.replace("/", "")
        is_cali = request.headers.get("X-CALI-Flow") == "true"
        status_emoji = "✓" if 200 <= response.status_code < 300 else "✗"
        cali_tag = " [CALI]" if is_cali else ""
        logger.info(f"[{timestamp}] {status_emoji} {endpoint} ({process_time:.1f}s){cali_tag}")

    return response

# ----------------- Rutas Honeypot -----------------

honeypot_routes = [
    "/etcpasswd", "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/mysql", "/sql", "/db", 
    "/xmlrpc.php", "/wp-config.php", "/.env", "/.git",
    "/console", "/manager", "/jmx-console", "/web-console",
    "/shell", "/cmd", "/api/v1", "/api/v2",
    "/backup", "/backups", "/old", "/test",
    "/index.php", "/index.html", "/default.php",
    "/_next", "/static", "/assets", "/uploads"
]

# ----------------- Comandos válidos -----------------

HELP_TEXT = (
    "Comandos:\n"
    "- ping -> pong <ms>\n"
    "- codem -> Situacion CODEM (DNI o CUIT)\n"
    "- nosis -> CUIL y nombre (DNI)\n"
    "- nosis2 -> CUIL y nombre desde CuitOnline (DNI + filtro opcional)\n"
    "- nosis3 -> CUIL y nombre desde AFIP A13 (DNI/CUIL + filtro opcional)\n"
    "- aportes -> Aportes de todos los empleadores (CUIL)\n"
    "- arca -> Consulta detallada de aportes en texto (CUIL)\n"
    "- sss -> Consulta traspasos y padrón SSS (DNI o CUIL)\n"
    "- blanco -> Consulta trabajo registrado en AFIP TREB (CUIL)\n"
)

@app.get("/", response_class=PlainTextResponse)
async def root():
    return "OK"

@app.get("/help", response_class=PlainTextResponse)
def help_text():
    return HELP_TEXT

@app.get("/codem", response_class=PlainTextResponse)
@limiter.limit("30/minute")
async def codem(request: Request, doc: str):
    kind, num = process_input(doc)
    if not num:
        raise HTTPException(status_code=400, detail="Uso: /codem?doc=<DNI|CUIT>")
    clean_value, value_type = normalize_cuil_dni(num)
    cache_key = clean_value
    cached = get_from_cache('codem', cache_key)
    if cached is not None:
        return cached
    resultado = await scrape_anses(num, lambda _: None)
    if _codem_should_cache(resultado):
        save_to_cache('codem', cache_key, resultado)
    return resultado

@app.get("/nosis")
@limiter.limit("30/minute")
async def nosis(request: Request, dni: str, nombre: str = None):
    clean_value, value_type = normalize_cuil_dni(dni)
    cache_key = clean_value if clean_value else dni
    cached = get_from_cache('nosis', cache_key)
    if cached is not None:
        return JSONResponse(cached)
    cuil, nombre_resultado = await nosis_lookup(dni, nombre)
    if not cuil or not nombre_resultado:
        return JSONResponse({"ok": False, "error": "No se pudo obtener informacion para ese DNI."})
    result = {"ok": True, "cuil": cuil, "nombre": nombre_resultado}
    save_to_cache('nosis', cache_key, result)
    return result

@app.get("/nosis2")
@limiter.limit("30/minute")
async def nosis2(request: Request, dni: str, nombre: str = None):
    clean_value, value_type = normalize_cuil_dni(dni)
    cache_key = clean_value if clean_value else dni
    cached = get_from_cache('nosis2', cache_key)
    if cached is not None:
        return JSONResponse(cached)
    cuil, nombre_resultado = await nosis2_lookup(dni, nombre)
    if not cuil or not nombre_resultado:
        return JSONResponse({"ok": False, "error": "No se pudo obtener informacion para ese DNI."})
    result = {"ok": True, "cuil": cuil, "nombre": nombre_resultado}
    save_to_cache('nosis2', cache_key, result)
    return result

@app.get("/nosis3")
@limiter.limit("30/minute")
async def nosis3(request: Request, dni: str, nombre: str = None):
    clean_value, value_type = normalize_cuil_dni(dni)
    cache_key = clean_value if clean_value else dni
    cached = get_from_cache('nosis3', cache_key)
    if cached is not None:
        return JSONResponse(cached)
    cuil, nombre_resultado, fecha_nac = await nosis3_lookup(dni, nombre)
    if not cuil or not nombre_resultado:
        return JSONResponse({"ok": False, "error": "No se pudo obtener informacion para ese DNI/CUIL."})
    result = {"ok": True, "cuil": cuil, "nombre": nombre_resultado, "fecha_nacimiento": fecha_nac}
    save_to_cache('nosis3', cache_key, result)
    return result

@app.get("/arca")
@limiter.limit("30/minute")
async def arca(request: Request, cuil: str):
    clean_cuil, cuil_type = normalize_cuil_dni(cuil)
    if cuil_type != 'cuil' or len(clean_cuil) != 11:
        return JSONResponse({"ok": False, "error": "Debe proporcionar un CUIL válido de 11 dígitos"})
    cached = get_from_cache('arca', clean_cuil)
    if cached is not None:
        return JSONResponse(cached)
    result_str = await arca_lookup(clean_cuil)
    result = json.loads(result_str)
    if _arca_should_cache(result):
        save_to_cache('arca', clean_cuil, result)
    return JSONResponse(result)

@app.get("/arcaprueba")
@limiter.limit("30/minute")
async def arcaprueba(request: Request, cuil: str):
    result_str = await arca_lookup(cuil)
    return JSONResponse(json.loads(result_str))

@app.get("/sss")
@limiter.limit("10/minute")
async def sss(request: Request, cuil_o_dni: str):
    clean_value, value_type = normalize_cuil_dni(cuil_o_dni)
    if value_type == 'unknown':
        return JSONResponse({"ok": False, "error": "Debe proporcionar un DNI o CUIL válido"})
    only_traspasos = request.headers.get('X-Only-Traspasos', '').lower() == 'true'
    print(f"[DEBUG SSS] CUIL: {clean_value}, X-Only-Traspasos: {only_traspasos}")
    cache_key = clean_value
    if not only_traspasos:
        cached = get_from_cache('sss', cache_key)
        if cached is not None:
            return JSONResponse(cached)
    resultado = await sss_lookup(cuil_o_dni, only_traspasos=only_traspasos)
    if _sss_should_cache(resultado) and not only_traspasos:
        save_to_cache('sss', cache_key, resultado)
    return JSONResponse(resultado)

@app.get("/blanco")
@limiter.limit("10/minute")
async def blanco(request: Request, cuil: str):
    try:
        resultado = await blanco_lookup(cuil)
        return JSONResponse(resultado)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"ok": False, "error": "ERROR_INTERNO", "mensaje": f"Error interno del servidor: {str(e)}"})

@app.get("/mono_pagos")
@app.post("/mono_pagos")
@limiter.limit("10/minute")
async def mono_pagos(request: Request, cuil: str = None):
    if not cuil:
        cuil = request.query_params.get("cuil")
    if not cuil and request.method == "POST":
        try:
            body = await request.json()
            cuil = body.get("cuil")
        except:
            pass
    if not cuil:
        return JSONResponse({"ok": False, "error": "Debe enviar el CUIL o DNI"})
    clean_cuil, cuil_type = normalize_cuil_dni(cuil)
    if cuil_type != 'cuil' or len(clean_cuil) != 11:
        return JSONResponse({"ok": False, "error": "Debe proporcionar un CUIL válido de 11 dígitos"})
    cached = get_from_cache('mono_pagos', clean_cuil)
    if cached is not None:
        return JSONResponse(cached)
    resultado = await mono_pagos_lookup(clean_cuil)
    if _mono_pagos_should_cache(resultado):
        save_to_cache('mono_pagos', clean_cuil, resultado)
    return JSONResponse(resultado)

@app.get("/monotras")
@app.post("/monotras")
@limiter.limit("10/minute")
async def monotras(request: Request, cuil: str = None):
    if not cuil:
        cuil = request.query_params.get("cuil")
    if not cuil and request.method == "POST":
        try:
            body = await request.json()
            cuil = body.get("cuil")
        except:
            pass
    if not cuil:
        return JSONResponse({"ok": False, "error": "Debe enviar el CUIL o DNI"})
    clean_cuil, cuil_type = normalize_cuil_dni(cuil)
    if cuil_type != 'cuil' or len(clean_cuil) != 11:
        return JSONResponse({"ok": False, "error": "Debe proporcionar un CUIL válido de 11 dígitos"})
    cached = get_from_cache('monotras', clean_cuil)
    if cached is not None:
        return JSONResponse(cached)
    resultado = await monotras_lookup(clean_cuil)
    if _monotras_should_cache(resultado):
        save_to_cache('monotras', clean_cuil, resultado)
    return JSONResponse(resultado)

# ----------------- Endpoints de gestión de cache -----------------

@app.get("/cache_flow/{cuil_o_dni}")
@limiter.limit("30/minute")
async def get_cache_flow(request: Request, cuil_o_dni: str):
    clean_value, value_type = normalize_cuil_dni(cuil_o_dni)
    cached = get_from_cache('flow', clean_value)
    if cached is not None:
        return JSONResponse(cached)
    return JSONResponse({"ok": False, "error": "No hay cache disponible para este CUIL/DNI"})

@app.post("/cache_flow")
@limiter.limit("30/minute")
async def save_cache_flow(request: Request):
    try:
        body = await request.json()
        cuil = body.get("cuil")
        command = body.get("command")
        messages = body.get("messages")
        if not cuil or not command or not messages:
            return JSONResponse({"ok": False, "error": "Debe enviar cuil, command y messages"})
        clean_cuil, cuil_type = normalize_cuil_dni(cuil)
        if cuil_type != 'cuil' or len(clean_cuil) != 11:
            return JSONResponse({"ok": False, "error": "Debe proporcionar un CUIL válido de 11 dígitos"})
        cache_data = {
            "ok": True, "cuil": clean_cuil, "command": command,
            "messages": messages, "cached_timestamp": datetime.now().timestamp() * 1000
        }
        save_to_cache('flow', clean_cuil, cache_data)
        return JSONResponse({"ok": True, "message": "Cache guardada exitosamente"})
    except Exception as e:
        logger.error(f"[CACHE-FLOW] Error guardando: {e}")
        return JSONResponse({"ok": False, "error": str(e)})

@app.delete("/clearcache/{cuil_o_dni}")
@limiter.limit("30/minute")
async def clear_cache(request: Request, cuil_o_dni: str):
    clean_value, value_type = normalize_cuil_dni(cuil_o_dni)
    if value_type == 'unknown':
        return JSONResponse({"ok": False, "error": "Debe proporcionar un DNI o CUIL válido"})
    deleted = delete_all_for_cuil(clean_value)
    return JSONResponse({"ok": True, "message": f"Cache eliminada para {clean_value}", "entries_deleted": deleted})

@app.get("/cache_stats")
@limiter.limit("30/minute")
async def cache_stats(request: Request):
    stats = get_cache_stats()
    return JSONResponse(stats)

# ----------------- COMBINED NOSIS -----------------

@app.get("/combined_nosis/{input_val}")
@limiter.limit("10/minute")
async def get_combined_nosis(request: Request, input_val: str, nombre: str = None):
    client_ip = get_remote_address_filtered(request)
    logger.info(f"[COMBINED] Solicitud para {input_val} desde {client_ip}")
    clean_value, value_type = normalize_cuil_dni(input_val)
    cache_key = clean_value if clean_value else input_val
    cached = get_from_cache('combined_nosis', cache_key)
    if cached is not None:
        return JSONResponse(cached)
    try:
        resultado, status, fecha = await nosis3_lookup(input_val, nombre)
        if status not in ["ERROR", "NO_MATCH", "MULTIPLE_RESULTS"]:
            result_dict = {"fuente": "nosis3", "cuil": resultado, "nombre": status if status != "OK" else nombre, "fecha_nacimiento": fecha, "status": "success"}
            save_to_cache('combined_nosis', cache_key, result_dict)
            return result_dict
    except Exception as e:
        logger.error(f"[COMBINED] Error en nosis3: {e}")
    try:
        resultado, status = await nosis2_lookup(input_val, nombre)
        if status not in ["ERROR", "NO_MATCH"]:
            result_dict = {"fuente": "nosis2", "cuil": resultado, "nombre": status, "status": "success"}
            save_to_cache('combined_nosis', cache_key, result_dict)
            return result_dict
    except Exception as e:
        logger.error(f"[COMBINED] Error en nosis2: {e}")
    try:
        resultado, status = await nosis_lookup(input_val, nombre)
        if status not in ["ERROR", "NO_MATCH", "MULTIPLE_RESULTS", None]:
            result_dict = {"fuente": "nosis", "cuil": resultado, "nombre": status, "status": "success"}
            save_to_cache('combined_nosis', cache_key, result_dict)
            return result_dict
    except Exception as e:
        logger.error(f"[COMBINED] Error en nosis: {e}")
    raise HTTPException(status_code=404, detail="No se encontró información en ninguna de las fuentes disponibles.")


# ----------------- Heartbeat hacia Healthchecks -----------------

async def _hc_heartbeat():
    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            try:
                await client.get(HC_CORE)
            except Exception:
                pass
            await asyncio.sleep(270)

async def _cache_cleanup():
    while True:
        await asyncio.sleep(86400)
        try:
            deleted = cleanup_expired_cache()
            if deleted > 0:
                logger.info(f"[CACHE-CLEANUP] {deleted} archivos expirados eliminados")
        except Exception as e:
            logger.error(f"[CACHE-CLEANUP] Error: {e}")


# ─────────────────────────────────────────────
# AUTH — Sistema de usuarios para app promotores
# ─────────────────────────────────────────────

from supabase import create_client, Client

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
_tokens: dict = {}

@app.post("/auth/login")
async def auth_login(body: dict = Body(...)):
    usuario = body.get("usuario", "").strip().lower()
    password = body.get("pass", "")
    
    # Buscamos al usuario directamente en Supabase
    response = supabase.table("usuarios").select("*").eq("usuario", usuario).execute()
    usuarios_db = response.data
    
    if not usuarios_db:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
        
    user = usuarios_db[0] # Tomamos el primer resultado
    
    if not user.get("activo", True):
        raise HTTPException(status_code=403, detail="Usuario desactivado")
    if user["pass"] != password:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
        
    token = secrets.token_hex(32)
    nombre_completo = (user.get("apellido", "") + " " + user.get("nombre", "")).strip()
    
    _tokens[token] = {
        "usuario": user["usuario"],
        "nombre": user["nombre"],
        "apellido": user.get("apellido", ""),
        "nombre_completo": nombre_completo,
        "esAdmin": user.get("esAdmin", False)
    }
    
    return {
        "ok": True, "token": token,
        "nombre": user["nombre"],
        "apellido": user.get("apellido", ""),
        "nombre_completo": nombre_completo,
        "esAdmin": user.get("esAdmin", False),
        "usuario": user["usuario"]
    }

@app.get("/auth/verify")
async def auth_verify(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token not in _tokens:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    return {"ok": True, **_tokens[token]}

@app.get("/auth/users")
async def auth_list_users(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token not in _tokens or not _tokens[token].get("esAdmin"):
        raise HTTPException(status_code=403, detail="Sin permisos")
        
    response = supabase.table("usuarios").select("id, usuario, nombre, apellido, activo, esAdmin").execute()
    return {"ok": True, "usuarios": response.data}

@app.post("/auth/users")
async def auth_create_user(request: Request, body: dict = Body(...)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token not in _tokens or not _tokens[token].get("esAdmin"):
        raise HTTPException(status_code=403, detail="Sin permisos")
    
    nuevo_usuario = {
        "usuario": body["usuario"].strip().lower(),
        "pass": body["pass"],
        "nombre": body["nombre"],
        "apellido": body.get("apellido", ""),
        "activo": True,
        "esAdmin": body.get("esAdmin", False)
    }
    
    try:
        response = supabase.table("usuarios").insert(nuevo_usuario).execute()
        nuevo = response.data[0]
        return {"ok": True, "usuario": {k: v for k, v in nuevo.items() if k != "pass"}}
    except Exception as e:
        # AQUÍ IMPRIMIMOS EL ERROR REAL EN LA CONSOLA DEL SERVIDOR
        print(f"\n--- ERROR SUPABASE AL CREAR USUARIO ---\n{str(e)}\n---------------------------------------")
        raise HTTPException(status_code=400, detail=f"Fallo en BD: {str(e)}")

@app.patch("/auth/users/{usuario_id}")
async def auth_update_user(usuario_id: str, request: Request, body: dict = Body(...)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token not in _tokens or not _tokens[token].get("esAdmin"):
        raise HTTPException(status_code=403, detail="Sin permisos")
    
    update_data = {}
    for campo in ["activo", "nombre", "apellido", "pass"]:
        if campo in body:
            update_data[campo] = body[campo]
            
    try:
        response = supabase.table("usuarios").update(update_data).eq("id", usuario_id).execute()
        
        if not response.data:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
            
        updated_user = response.data[0]
        
        if "activo" in body and not body["activo"]:
            for t, info in list(_tokens.items()):
                if info["usuario"] == updated_user["usuario"]:
                    del _tokens[t]
                    
        return {"ok": True, "usuario": {k: v for k, v in updated_user.items() if k != "pass"}}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al actualizar el usuario: {str(e)}")

@app.delete("/auth/users/{usuario_id}")
async def auth_delete_user(usuario_id: str, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token not in _tokens or not _tokens[token].get("esAdmin"):
        raise HTTPException(status_code=403, detail="Sin permisos")
        
    # Primero buscamos al usuario para verificar si existe y si es admin
    response = supabase.table("usuarios").select("*").eq("id", usuario_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
    user = response.data[0]
    
    if user.get("esAdmin"):
        raise HTTPException(status_code=400, detail="No se puede eliminar un admin")
        
    try:
        # Lo eliminamos de Supabase
        supabase.table("usuarios").delete().eq("id", usuario_id).execute()
        
        # Eliminamos sus sesiones activas de la memoria
        for t, info in list(_tokens.items()):
            if info["usuario"] == user["usuario"]:
                del _tokens[t]
                
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al eliminar el usuario: {str(e)}")


# ----------------- HONEYPOTS Y CATCH-ALL (AL FINAL) -----------------

for route in honeypot_routes:
    @app.get(route)
    @app.post(route)
    async def honeypot(request: Request):
        client_ip = get_remote_address_filtered(request)
        logger.warning(f"[HONEYPOT] Intento sospechoso desde {client_ip} en ruta {request.url.path}")
        ban_ip(client_ip)
        raise HTTPException(status_code=403, detail="Access Denied")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    client_ip = get_remote_address_filtered(request)
    legitimate_routes = [
        "", "help", "codem", "nosis", "nosis2", "nosis3", "combined_nosis",
        "aportes", "arca", "arcaprueba", "sss", "blanco", "mono_pagos", "monotras",
        "favicon.ico", "cache_stats", "cache_flow", "clearcache",
        "auth/login", "auth/verify", "auth/users", "api"
    ]
    if path not in legitimate_routes and not path.startswith("combined_nosis/") \
       and not path.startswith("clearcache/") and not path.startswith("cache_flow/") \
       and not path.startswith("auth/users/"):
        logger.warning(f"[404] Ruta inválida desde {client_ip}: /{path}")
        # ban_ip(client_ip)
        raise HTTPException(status_code=404, detail="Not Found")
    raise HTTPException(status_code=404, detail="Not Found")

# ----------------- STARTUP -----------------

@app.on_event("startup")
async def _hc_start():
    try:
        deleted = cleanup_expired_cache()
        logger.info(f"[STARTUP] Limpieza inicial de cache: {deleted} archivos expirados eliminados")
    except Exception as e:
        logger.error(f"[STARTUP] Error en limpieza inicial de cache: {e}")
    app.state._hc_task = asyncio.create_task(_hc_heartbeat())
    app.state._cache_cleanup_task = asyncio.create_task(_cache_cleanup())
    logger.info("[STARTUP] Sistema de cache iniciado con limpieza automática cada 24 horas")