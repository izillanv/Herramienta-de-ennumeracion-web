#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
  cabeceras_seguridad.py  -  Analizador de cabeceras de seguridad HTTP
===============================================================================
  Autor : Izan Villalba

  Hace una peticion HTTP(S) a la URL indicada y analiza las CABECERAS DE
  SEGURIDAD de la respuesta: comprueba cuales estan presentes, cuales faltan,
  si estan bien configuradas, y da una PUNTUACION (A..F) con recomendaciones.

  Tambien analiza:
      - El servidor y tecnologias que se "chivan" en las cabeceras.
      - Los atributos de seguridad de las cookies (Secure, HttpOnly, SameSite).

  Cabeceras evaluadas:
      Strict-Transport-Security (HSTS)   Content-Security-Policy (CSP)
      X-Frame-Options                    X-Content-Type-Options
      Referrer-Policy                    Permissions-Policy
      Cross-Origin-Opener-Policy         Cross-Origin-Embedder-Policy
      Cross-Origin-Resource-Policy       Cache-Control (en respuestas sensibles)

  Uso:
      python cabeceras_seguridad.py https://ejemplo.com
      python cabeceras_seguridad.py ejemplo.com otra.com --html informe.html

  Solo libreria estandar. No requiere instalar nada.
===============================================================================
"""

import argparse
import html
import os
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime

# ---------------------------------------------------------------------------
#  Colores de consola
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"; GREY = "\033[90m"

USAR_COLOR = True

def _habilitar_terminal():
    global USAR_COLOR
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            USAR_COLOR = False
    if not sys.stdout.isatty() and os.name != "nt":
        USAR_COLOR = False

def c(t, col):
    return f"{col}{t}{C.RESET}" if USAR_COLOR else str(t)

def banner():
    print(c(r"""
   ____      _               _             ____
  / ___|__ _| |__   ___  ___| |_ ___ _ __ |  _ \ ___  ___
 | |   / _` | '_ \ / _ \/ __| __/ _ \ '__|| | | / _ \/ __|
 | |__| (_| | |_) |  __/ (__| ||  __/ |   | |_| |  __/\__ \
  \____\__,_|_.__/ \___|\___|\__\___|_|   |____/ \___||___/
        Analizador de cabeceras de seguridad HTTP
""", C.CYAN))

def titulo(t):
    print("\n" + c("=" * 72, C.BLUE))
    print(c(f"  {t}", C.BOLD + C.CYAN))
    print(c("=" * 72, C.BLUE))

def sub(t):
    print("\n" + c(f"── {t} " + "─" * max(0, 66 - len(t)), C.MAGENTA))

# Badges de estado
def badge(estado):
    m = {
        "OK":    (C.GREEN,  "[ OK ]"),
        "WARN":  (C.YELLOW, "[WARN]"),
        "FAIL":  (C.RED,    "[FAIL]"),
        "INFO":  (C.BLUE,   "[INFO]"),
    }
    col, txt = m.get(estado, (C.GREY, "[ ?? ]"))
    return c(txt, col + C.BOLD)


# ===========================================================================
#  DEFINICION DE LAS CABECERAS DE SEGURIDAD Y SU EVALUACION
#  Cada entrada: nombre, peso (importancia), funcion evaluadora, explicacion.
#  La funcion evaluadora devuelve (estado, comentario).
# ===========================================================================
def ev_hsts(v):
    if v is None:
        return "FAIL", "Falta: el navegador puede conectarse por HTTP sin cifrar."
    bajo = v.lower()
    try:
        edad = int(bajo.split("max-age=")[1].split(";")[0].strip())
    except Exception:
        edad = 0
    if edad < 15552000:        # 180 dias
        return "WARN", f"Presente pero max-age bajo ({edad}s). Recomendado >= 15552000."
    extra = []
    if "includesubdomains" in bajo: extra.append("includeSubDomains")
    if "preload" in bajo: extra.append("preload")
    return "OK", "Correcta" + (f" ({', '.join(extra)})" if extra else "")

def ev_csp(v):
    if v is None:
        return "FAIL", "Falta: sin defensa declarativa frente a XSS e inyeccion de contenido."
    bajo = v.lower()
    if "unsafe-inline" in bajo or "unsafe-eval" in bajo:
        return "WARN", "Presente pero usa 'unsafe-inline'/'unsafe-eval' (debilita la proteccion)."
    if "default-src" not in bajo and "script-src" not in bajo:
        return "WARN", "Presente pero sin default-src/script-src definido."
    return "OK", "Definida con directivas restrictivas."

def ev_xfo(v):
    if v is None:
        return "FAIL", "Falta: posible clickjacking (la pagina puede embeberse en un iframe)."
    if v.strip().upper() in ("DENY", "SAMEORIGIN"):
        return "OK", f"Correcta ({v.strip()})."
    return "WARN", f"Valor poco habitual: {v}"

def ev_xcto(v):
    if v is None:
        return "FAIL", "Falta: el navegador puede 'adivinar' tipos MIME (MIME sniffing)."
    if v.strip().lower() == "nosniff":
        return "OK", "Correcta (nosniff)."
    return "WARN", f"Valor inesperado: {v}"

def ev_refpol(v):
    if v is None:
        return "WARN", "Falta: puede filtrarse la URL de origen en la cabecera Referer."
    seguras = ("no-referrer", "strict-origin", "same-origin", "strict-origin-when-cross-origin")
    if any(s in v.lower() for s in seguras):
        return "OK", f"Correcta ({v})."
    return "WARN", f"Politica poco restrictiva: {v}"

def ev_permpol(v):
    if v is None:
        return "WARN", "Falta: no se restringen APIs del navegador (camara, micro, geoloc...)."
    return "OK", "Presente (revisa que limite las APIs sensibles)."

def ev_coop(v):
    if v is None:
        return "WARN", "Falta: recomendable 'same-origin' para aislar la ventana."
    return "OK", f"Presente ({v})."

def ev_coep(v):
    if v is None:
        return "INFO", "Opcional: 'require-corp' habilita aislamiento de origen cruzado."
    return "OK", f"Presente ({v})."

def ev_corp(v):
    if v is None:
        return "INFO", "Opcional: controla quien puede cargar este recurso."
    return "OK", f"Presente ({v})."

# nombre cabecera -> (peso, evaluador, descripcion corta)
CABECERAS = [
    ("Strict-Transport-Security", 20, ev_hsts,
     "Fuerza HTTPS en el navegador durante max-age segundos."),
    ("Content-Security-Policy",    20, ev_csp,
     "Lista blanca de origenes de scripts/estilos; mitiga XSS."),
    ("X-Frame-Options",            12, ev_xfo,
     "Impide que la pagina se cargue en iframes (anti-clickjacking)."),
    ("X-Content-Type-Options",     12, ev_xcto,
     "Desactiva el MIME sniffing del navegador."),
    ("Referrer-Policy",            10, ev_refpol,
     "Controla cuanta info de URL se envia al navegar a otros sitios."),
    ("Permissions-Policy",         10, ev_permpol,
     "Restringe APIs del navegador (camara, microfono, geolocalizacion)."),
    ("Cross-Origin-Opener-Policy",  6, ev_coop,
     "Aisla el contexto de navegacion de otras ventanas."),
    ("Cross-Origin-Embedder-Policy",5, ev_coep,
     "Exige que los recursos embebidos concedan permiso explicito."),
    ("Cross-Origin-Resource-Policy",5, ev_corp,
     "Define quien puede incrustar este recurso."),
]

# Cabeceras que REVELAN informacion (fingerprinting del servidor)
CABECERAS_FUGA = ["Server", "X-Powered-By", "X-AspNet-Version",
                  "X-AspNetMvc-Version", "X-Generator", "Via", "X-Runtime"]


# ===========================================================================
#  PETICION HTTP
# ===========================================================================
def normaliza_url(u):
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u

def pedir(url, timeout=12):
    url = normaliza_url(url)
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (analizador-cabeceras/1.0)"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.geturl(), r.status, dict(r.headers), None
    except urllib.error.HTTPError as e:
        # Una respuesta 4xx/5xx tambien trae cabeceras utiles
        return url, e.code, dict(e.headers), None
    except Exception as e:
        return url, None, {}, str(e)

def buscar_cabecera(cabeceras, nombre):
    """Busqueda insensible a mayusculas/minusculas."""
    for k, v in cabeceras.items():
        if k.lower() == nombre.lower():
            return v
    return None


# ===========================================================================
#  ANALISIS
# ===========================================================================
def analizar(url):
    url_final, status, cabeceras, error = pedir(url)
    resultado = {"url": url, "url_final": url_final, "status": status,
                 "error": error, "cabeceras": cabeceras,
                 "evaluacion": [], "fugas": [], "cookies": [],
                 "puntos": 0, "max_puntos": 0, "nota": "F"}
    if error:
        return resultado

    for nombre, peso, evaluador, desc in CABECERAS:
        valor = buscar_cabecera(cabeceras, nombre)
        estado, comentario = evaluador(valor)
        # Puntuacion: OK=peso, WARN=mitad, INFO/FAIL=0
        if estado == "OK":
            ganado = peso
        elif estado == "WARN":
            ganado = peso // 2
        else:
            ganado = 0
        # Las cabeceras "INFO" (opcionales) no cuentan para el maximo
        if estado != "INFO":
            resultado["max_puntos"] += peso
            resultado["puntos"] += ganado
        resultado["evaluacion"].append(
            {"nombre": nombre, "estado": estado, "valor": valor or "—",
             "comentario": comentario, "desc": desc})

    # Fugas de informacion
    for nombre in CABECERAS_FUGA:
        valor = buscar_cabecera(cabeceras, nombre)
        if valor:
            resultado["fugas"].append((nombre, valor))

    # Cookies
    for k, v in cabeceras.items():
        if k.lower() == "set-cookie":
            bajo = v.lower()
            resultado["cookies"].append({
                "cookie": v.split("=")[0],
                "secure": "secure" in bajo,
                "httponly": "httponly" in bajo,
                "samesite": next((p.split("=")[1].strip()
                                  for p in v.split(";")
                                  if p.strip().lower().startswith("samesite")), "—"),
            })

    # Nota final
    pct = (resultado["puntos"] / resultado["max_puntos"] * 100) if resultado["max_puntos"] else 0
    resultado["pct"] = round(pct)
    resultado["nota"] = ("A" if pct >= 90 else "B" if pct >= 75 else
                         "C" if pct >= 60 else "D" if pct >= 40 else
                         "E" if pct >= 20 else "F")
    return resultado


# ===========================================================================
#  SALIDA EN CONSOLA
# ===========================================================================
def _color_nota(nota):
    return {"A": C.GREEN, "B": C.GREEN, "C": C.YELLOW,
            "D": C.YELLOW, "E": C.RED, "F": C.RED}.get(nota, C.GREY)

def _barra(pct, ancho=30):
    llenos = round(pct / 100 * ancho)
    col = C.GREEN if pct >= 75 else C.YELLOW if pct >= 40 else C.RED
    return c("█" * llenos, col) + c("░" * (ancho - llenos), C.GREY)

def mostrar_consola(r):
    titulo(f"ANALISIS: {r['url']}")
    if r["error"]:
        print(f"  {badge('FAIL')} No se pudo conectar: {c(r['error'], C.RED)}")
        return
    if r["url_final"] != normaliza_url(r["url"]):
        print(f"  {badge('INFO')} Redirigido a: {c(r['url_final'], C.CYAN)}")
    print(f"  {badge('INFO')} Codigo HTTP: {c(r['status'], C.BOLD)}")

    sub("Cabeceras de seguridad")
    for e in r["evaluacion"]:
        print(f"  {badge(e['estado'])} {c(e['nombre'], C.BOLD)}")
        print(f"         {c('valor:', C.DIM)} {e['valor']}")
        col = C.GREEN if e["estado"] == "OK" else C.YELLOW if e["estado"] in ("WARN", "INFO") else C.RED
        print(f"         {c('→ ' + e['comentario'], col)}")

    if r["fugas"]:
        sub("Fugas de informacion (fingerprinting del servidor)")
        for nombre, valor in r["fugas"]:
            print(f"  {badge('WARN')} {c(nombre, C.BOLD)}: {c(valor, C.YELLOW)}")
            print(f"         {c('→ revela software/version; facilita buscar exploits', C.DIM)}")
    else:
        sub("Fugas de informacion")
        print(f"  {badge('OK')} El servidor no revela software ni versiones.")

    if r["cookies"]:
        sub("Cookies")
        for ck in r["cookies"]:
            flags = []
            flags.append(c("Secure", C.GREEN) if ck["secure"] else c("sin Secure", C.RED))
            flags.append(c("HttpOnly", C.GREEN) if ck["httponly"] else c("sin HttpOnly", C.RED))
            flags.append(f"SameSite={ck['samesite']}")
            print(f"  {badge('OK' if ck['secure'] and ck['httponly'] else 'WARN')} "
                  f"{c(ck['cookie'], C.BOLD)} · " + " · ".join(flags))

    # Puntuacion
    titulo("PUNTUACION")
    nota = r["nota"]
    print(f"\n   {c('NOTA:', C.BOLD)}  {c(' ' + nota + ' ', _color_nota(nota) + C.BOLD)}"
          f"   {r['puntos']}/{r['max_puntos']} puntos  ({r['pct']}%)")
    print(f"   {_barra(r['pct'])}  {r['pct']}%\n")


# ===========================================================================
#  INFORME HTML
# ===========================================================================
def generar_html(resultados, ruta):
    def esc(x): return html.escape(str(x))
    color_estado = {"OK": "#3fb950", "WARN": "#d29922", "FAIL": "#f85149", "INFO": "#58a6ff"}
    color_nota = {"A": "#3fb950", "B": "#3fb950", "C": "#d29922",
                  "D": "#d29922", "E": "#f85149", "F": "#f85149"}
    tarjetas = ""
    for r in resultados:
        if r["error"]:
            tarjetas += f"""<section><h2>{esc(r['url'])}</h2>
              <p class="fail">No se pudo conectar: {esc(r['error'])}</p></section>"""
            continue
        filas = ""
        for e in r["evaluacion"]:
            col = color_estado[e["estado"]]
            filas += f"""<tr>
              <td><span class="badge" style="background:{col}22;color:{col}">{e['estado']}</span></td>
              <td><b>{esc(e['nombre'])}</b><div class="desc">{esc(e['desc'])}</div></td>
              <td><code>{esc(e['valor'])}</code></td>
              <td>{esc(e['comentario'])}</td></tr>"""
        fugas = "".join(f"<tr><td><b>{esc(n)}</b></td><td><code>{esc(v)}</code></td></tr>"
                        for n, v in r["fugas"]) or '<tr><td colspan="2" class="ok">Ninguna</td></tr>'
        cookies = ""
        for ck in r["cookies"]:
            def flag(b, t):
                return (f'<span class="ok">{t}</span>' if b
                        else f'<span class="fail">sin {t}</span>')
            cookies += (f"<tr><td><b>{esc(ck['cookie'])}</b></td>"
                        f"<td>{flag(ck['secure'],'Secure')}</td>"
                        f"<td>{flag(ck['httponly'],'HttpOnly')}</td>"
                        f"<td>SameSite={esc(ck['samesite'])}</td></tr>")
        if not cookies:
            cookies = '<tr><td colspan="4" class="desc">Sin cookies en la respuesta</td></tr>'
        cn = color_nota[r["nota"]]
        tarjetas += f"""<section>
          <div class="cab">
            <h2>{esc(r['url'])}</h2>
            <div class="nota" style="background:{cn}22;color:{cn};border-color:{cn}">
              {r['nota']}<span>{r['pct']}%</span></div>
          </div>
          <p class="meta">HTTP {esc(r['status'])} · {esc(r['url_final'])} ·
             {r['puntos']}/{r['max_puntos']} puntos</p>
          <div class="barra"><div style="width:{r['pct']}%;background:{cn}"></div></div>
          <h3>Cabeceras de seguridad</h3>
          <table><thead><tr><th>Estado</th><th>Cabecera</th><th>Valor</th><th>Observacion</th></tr></thead>
          <tbody>{filas}</tbody></table>
          <h3>Fugas de informacion</h3>
          <table><tbody>{fugas}</tbody></table>
          <h3>Cookies</h3>
          <table><tbody>{cookies}</tbody></table>
        </section>"""
    doc = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de cabeceras de seguridad</title>
<style>
 :root{{--bg:#0d1117;--card:#161b22;--line:#30363d;--txt:#e6edf3;--mut:#8b949e;--bl:#58a6ff;}}
 *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--txt);
   font:15px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif}}
 header{{padding:30px 24px;background:linear-gradient(135deg,#0d1117,#13233a);border-bottom:2px solid var(--bl)}}
 header h1{{margin:0;font-size:23px}} header .meta{{color:var(--mut);font-size:13px;margin-top:6px}}
 main{{max-width:1040px;margin:0 auto;padding:24px}}
 section{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 24px;margin:18px 0}}
 .cab{{display:flex;justify-content:space-between;align-items:center}}
 h2{{margin:0;font-size:19px;color:var(--bl);word-break:break-all}}
 h3{{margin:20px 0 8px;font-size:14px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}}
 .nota{{font-size:30px;font-weight:800;border:2px solid;border-radius:12px;padding:6px 16px;
   text-align:center;line-height:1}} .nota span{{display:block;font-size:12px;font-weight:600}}
 .meta{{color:var(--mut);font-size:13px;margin:6px 0 10px;word-break:break-all}}
 .barra{{height:8px;background:#0b0f14;border-radius:6px;overflow:hidden;margin-bottom:8px}}
 .barra div{{height:100%}}
 table{{width:100%;border-collapse:collapse;font-size:13.5px;margin-bottom:4px}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
 th{{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px}}
 code{{color:#39d0d8;word-break:break-all;font-size:12.5px}}
 .desc{{color:var(--mut);font-size:12px;margin-top:3px}}
 .badge{{padding:2px 9px;border-radius:20px;font-weight:700;font-size:12px}}
 .ok{{color:#3fb950}} .fail{{color:#f85149}}
 footer{{color:var(--mut);text-align:center;padding:24px;font-size:12px}}
</style></head><body>
<header><h1>Informe de cabeceras de seguridad HTTP</h1>
<div class="meta">Generado el {datetime.now():%d/%m/%Y %H:%M:%S} · cabeceras_seguridad.py</div></header>
<main>{tarjetas}</main>
<footer>El analisis se basa solo en las cabeceras de respuesta</footer>
</body></html>"""
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(doc)
    return ruta


# ===========================================================================
#  MAIN
# ===========================================================================
def main():
    p = argparse.ArgumentParser(
        description="Analizador de cabeceras de seguridad HTTP.",
        epilog="Ejemplo: python cabeceras_seguridad.py https://github.com --html informe.html")
    p.add_argument("urls", nargs="+", help="una o varias URLs a analizar")
    p.add_argument("--html", metavar="ARCHIVO",
                   help="nombre del informe HTML (si se omite, se genera uno automatico)")
    p.add_argument("--no-color", action="store_true", help="desactiva los colores")
    args = p.parse_args()

    global USAR_COLOR
    _habilitar_terminal()
    if args.no_color:
        USAR_COLOR = False

    banner()
    resultados = []
    for url in args.urls:
        r = analizar(url)
        resultados.append(r)
        mostrar_consola(r)

    # Siempre se genera un informe HTML. Con --html usa ese nombre; si no, uno automatico.
    if args.html:
        nombre = args.html
    else:
        base = args.urls[0].replace("https://", "").replace("http://", "").strip("/")
        base = "".join(ch if ch.isalnum() else "_" for ch in base)
        nombre = f"informe_cabeceras_{base}.html"
    ruta = generar_html(resultados, nombre)
    titulo("INFORME")
    print(f"  {badge('OK')} Informe HTML guardado en: {c(os.path.abspath(ruta), C.CYAN)}")
    if os.name == "nt":
        print(f"  {badge('INFO')} Abrelo con:  start {nombre}")
    else:
        print(f"  {badge('INFO')} Abrelo en el navegador: {os.path.abspath(ruta)}")

    print(c("\n  Analisis finalizado.\n", C.GREEN + C.BOLD))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n  Interrumpido por el usuario.\n", C.YELLOW))
