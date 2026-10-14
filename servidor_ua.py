#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
  servidor_ua.py  -  Servidor HTTP que captura y analiza el User-Agent
===============================================================================
  Autor : Izan Villalba

  Levanta un servidor HTTP. De CADA peticion que recibe:
      1. Captura la cabecera "User-Agent" (y la IP, metodo, ruta, hora).
      2. La PARSEA: navegador + version, sistema operativo, tipo de
         dispositivo (movil/tablet/escritorio) y si es un bot/herramienta.
      3. La guarda en memoria y en disco (capturas_ua.json).

  Como ENSEÑA la informacion:
      - Log en consola con colores, una linea por peticion.
      - Panel web EN VIVO en  http://localhost:PUERTO/  con:
            · contadores (total, IPs unicas, bots)
            · graficos de barras por navegador / SO / dispositivo
            · tabla de las ultimas peticiones
            · se refresca solo cada 2 segundos.
      - API JSON en  /api/data  (los mismos datos en crudo).

  Rutas:
      /            -> panel de control (no se cuenta como captura)
      /api/data    -> datos en JSON (no se cuenta como captura)
      cualquier otra ruta -> SE CAPTURA y se devuelve al visitante una
                             pagina con SU propio User-Agent ya analizado.

  Como probarlo (en otra terminal, con el servidor arrancado):
      curl http://localhost:8080/hola
      curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" http://localhost:8080/
      curl -A "Googlebot/2.1 (+http://www.google.com/bot.html)" http://localhost:8080/x
  ...o abre esas URLs en el navegador y mira el panel.

  Uso:
      python servidor_ua.py                 (puerto 8080)
      python servidor_ua.py --puerto 9000
      python servidor_ua.py --host 0.0.0.0  (accesible desde la red)

  Solo libreria estandar. No requiere instalar nada.
===============================================================================
"""

import argparse
import json
import os
import re
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


# ===========================================================================
#  PARSER DE USER-AGENT  (basado en expresiones regulares)
# ===========================================================================
# Bots / herramientas (orden: lo mas especifico primero)
BOTS = [
    (r"googlebot", "Googlebot"), (r"bingbot", "Bingbot"),
    (r"yandexbot", "YandexBot"), (r"duckduckbot", "DuckDuckBot"),
    (r"baiduspider", "Baidu Spider"), (r"ahrefsbot", "AhrefsBot"),
    (r"semrushbot", "SemrushBot"), (r"facebookexternalhit", "Facebook Bot"),
    (r"twitterbot", "Twitterbot"), (r"slackbot", "Slackbot"),
    (r"telegrambot", "TelegramBot"), (r"whatsapp", "WhatsApp"),
    (r"discordbot", "Discordbot"), (r"applebot", "Applebot"),
    (r"petalbot", "PetalBot"), (r"gptbot", "GPTBot"),
    (r"claudebot", "ClaudeBot"), (r"ccbot", "CCBot (Common Crawl)"),
    (r"curl", "curl"), (r"wget", "wget"),
    (r"python-requests", "python-requests"), (r"python-urllib|urllib", "python-urllib"),
    (r"go-http-client", "Go HTTP"), (r"java/", "Java"),
    (r"postmanruntime", "Postman"), (r"httpie", "HTTPie"),
    (r"nmap", "Nmap"), (r"nikto", "Nikto"), (r"sqlmap", "sqlmap"),
    (r"masscan", "masscan"), (r"zgrab", "ZGrab"),
    (r"bot|crawler|spider|crawl", "Bot generico"),
]

# Navegadores (orden importante: Edge/Opera/Brave antes que Chrome, etc.)
NAVEGADORES = [
    (r"edg(?:a|ios)?/([\d.]+)", "Edge"),
    (r"opr/([\d.]+)|opera[/ ]([\d.]+)", "Opera"),
    (r"samsungbrowser/([\d.]+)", "Samsung Internet"),
    (r"vivaldi/([\d.]+)", "Vivaldi"),
    (r"brave/([\d.]+)", "Brave"),
    (r"ucbrowser/([\d.]+)", "UC Browser"),
    (r"firefox/([\d.]+)|fxios/([\d.]+)", "Firefox"),
    (r"chrome/([\d.]+)|crios/([\d.]+)", "Chrome"),
    (r"version/([\d.]+).*safari", "Safari"),
    (r"msie ([\d.]+)|trident.*rv:([\d.]+)", "Internet Explorer"),
]

def _version_windows(nt):
    return {"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7",
            "6.0": "Vista", "5.1": "XP"}.get(nt, nt)

def parsear_ua(ua):
    """Devuelve un dict con navegador, version, SO, dispositivo, tipo y bot."""
    if not ua or ua == "-":
        return {"navegador": "Desconocido", "version": "", "so": "Desconocido",
                "dispositivo": "Desconocido", "tipo": "desconocido", "bot": False}
    low = ua.lower()

    # --- Bot? ---
    for patron, nombre in BOTS:
        if re.search(patron, low):
            return {"navegador": nombre, "version": "", "so": _detectar_so(ua, low),
                    "dispositivo": "Servidor/Bot", "tipo": "bot", "bot": True}

    # --- Navegador ---
    navegador, version = "Desconocido", ""
    for patron, nombre in NAVEGADORES:
        m = re.search(patron, low)
        if m:
            navegador = nombre
            version = next((g for g in m.groups() if g), "")
            break

    so = _detectar_so(ua, low)
    tipo, dispositivo = _detectar_dispositivo(low, so)
    return {"navegador": navegador, "version": version, "so": so,
            "dispositivo": dispositivo, "tipo": tipo, "bot": False}

def _detectar_so(ua, low):
    if "windows nt" in low:
        m = re.search(r"windows nt ([\d.]+)", low)
        return "Windows " + _version_windows(m.group(1)) if m else "Windows"
    if "android" in low:
        m = re.search(r"android ([\d.]+)", low)
        return "Android " + m.group(1) if m else "Android"
    if "iphone" in low or "ipad" in low or "ipod" in low:
        m = re.search(r"os ([\d_]+)", low)
        return "iOS " + m.group(1).replace("_", ".") if m else "iOS"
    if "mac os x" in low or "macintosh" in low:
        m = re.search(r"mac os x ([\d_]+)", low)
        return "macOS " + m.group(1).replace("_", ".") if m else "macOS"
    if "cros" in low:
        return "ChromeOS"
    if "linux" in low or "x11" in low:
        return "Linux"
    return "Desconocido"

def _detectar_dispositivo(low, so):
    if "ipad" in low or ("tablet" in low and "mobile" not in low) or ("android" in low and "mobile" not in low):
        return "tablet", "Tablet"
    if "mobi" in low or "iphone" in low or "ipod" in low or "android" in low or "windows phone" in low:
        return "movil", "Movil"
    return "escritorio", "Escritorio"


# ===========================================================================
#  ALMACEN DE CAPTURAS  (memoria + disco)
# ===========================================================================
class Almacen:
    def __init__(self, archivo):
        self.archivo = archivo
        self.lock = threading.Lock()
        self.capturas = []
        self._cargar()

    def _cargar(self):
        if os.path.exists(self.archivo):
            try:
                with open(self.archivo, encoding="utf-8") as f:
                    self.capturas = json.load(f)
            except Exception:
                self.capturas = []

    def _guardar(self):
        try:
            with open(self.archivo, "w", encoding="utf-8") as f:
                json.dump(self.capturas, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def añadir(self, captura):
        with self.lock:
            self.capturas.append(captura)
            self._guardar()
            return len(self.capturas)

    def datos(self):
        with self.lock:
            caps = list(self.capturas)
        total = len(caps)
        ips = {x["ip"] for x in caps}
        def cuenta(clave):
            d = {}
            for x in caps:
                k = x["ua"].get(clave) or "Desconocido"
                d[k] = d.get(k, 0) + 1
            return dict(sorted(d.items(), key=lambda kv: kv[1], reverse=True))
        return {
            "total": total,
            "ips_unicas": len(ips),
            "bots": sum(1 for x in caps if x["ua"]["bot"]),
            "navegadores": cuenta("navegador"),
            "sistemas": cuenta("so"),
            "dispositivos": cuenta("tipo"),
            "capturas": list(reversed(caps[-200:])),  # ultimas 200, mas recientes primero
        }


# ===========================================================================
#  MANEJADOR HTTP
# ===========================================================================
ALMACEN = None   # se asigna en main()
RUTAS_IGNORADAS = ("/", "/api/data", "/favicon.ico")

class Handler(BaseHTTPRequestHandler):
    server_version = "CapturaUA/1.0"

    # Silenciamos el log por defecto: usamos el nuestro con colores
    def log_message(self, *a):
        pass

    def _responder(self, codigo, cuerpo, tipo="text/html; charset=utf-8"):
        datos = cuerpo.encode("utf-8") if isinstance(cuerpo, str) else cuerpo
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self):
        ruta = self.path.split("?")[0]
        if ruta == "/" or ruta == "/panel":
            self._responder(200, PAGINA_PANEL)
        elif ruta == "/api/data":
            self._responder(200, json.dumps(ALMACEN.datos(), ensure_ascii=False),
                            "application/json; charset=utf-8")
        elif ruta == "/favicon.ico":
            self._responder(204, b"")
        else:
            self._capturar_y_responder()

    def do_POST(self):
        self._capturar_y_responder()

    def do_HEAD(self):
        self.send_response(200); self.end_headers()

    def _capturar_y_responder(self):
        ua_raw = self.headers.get("User-Agent", "-")
        analisis = parsear_ua(ua_raw)
        ip = self.client_address[0]
        captura = {
            "hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "metodo": self.command,
            "ruta": self.path,
            "ua_raw": ua_raw,
            "ua": analisis,
            # Guardamos tambien otras cabeceras utiles de la peticion
            "accept_language": self.headers.get("Accept-Language", "-"),
            "referer": self.headers.get("Referer", "-"),
        }
        n = ALMACEN.añadir(captura)
        self._log_consola(n, captura)
        self._responder(200, _pagina_visitante(captura))

    def _log_consola(self, n, cap):
        a = cap["ua"]
        etiqueta = (c("BOT", C.MAGENTA + C.BOLD) if a["bot"]
                    else c(a["tipo"].upper(), C.BLUE))
        print(
            c(f"[{cap['hora']}]", C.GREY) + " "
            + c(f"#{n:<4}", C.DIM) + " "
            + c(f"{cap['ip']:<15}", C.CYAN) + " "
            + c(f"{cap['metodo']:<4}", C.YELLOW) + " "
            + c(f"{cap['ruta'][:22]:<22}", C.GREY) + "  "
            + etiqueta + " "
            + c(f"{a['navegador']} {a['version']}".strip(), C.GREEN + C.BOLD) + " · "
            + c(a["so"], C.GREEN)
        )


# ===========================================================================
#  PAGINA PARA EL VISITANTE  (le devolvemos SU propio User-Agent analizado)
# ===========================================================================
def _pagina_visitante(cap):
    a = cap["ua"]
    import html as _h
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Peticion capturada</title>
<style>
 body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
   background:#0d1117;color:#e6edf3;font:16px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif}}
 .caja{{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:30px 34px;max-width:560px}}
 h1{{margin:0 0 4px;font-size:20px;color:#39d0d8}} p.sub{{margin:0 0 18px;color:#8b949e;font-size:14px}}
 table{{width:100%;border-collapse:collapse}} td{{padding:7px 4px;border-bottom:1px solid #21262d}}
 td.k{{color:#8b949e;width:140px}} td.v{{color:#3fb950;font-weight:600}}
 .raw{{margin-top:14px;background:#0b0f14;border:1px solid #30363d;border-radius:8px;
   padding:10px;font-size:12px;color:#8b949e;word-break:break-all}}
 a{{color:#58a6ff}}
</style></head><body><div class="caja">
<h1>✓ Tu peticion ha sido capturada</h1>
<p class="sub">Este servidor ha leido tu cabecera User-Agent y la ha analizado:</p>
<table>
 <tr><td class="k">Navegador</td><td class="v">{_h.escape(a['navegador'])} {_h.escape(a['version'])}</td></tr>
 <tr><td class="k">Sistema</td><td class="v">{_h.escape(a['so'])}</td></tr>
 <tr><td class="k">Dispositivo</td><td class="v">{_h.escape(a['dispositivo'])}</td></tr>
 <tr><td class="k">¿Es un bot?</td><td class="v">{'Si' if a['bot'] else 'No'}</td></tr>
 <tr><td class="k">Tu IP</td><td class="v">{_h.escape(cap['ip'])}</td></tr>
</table>
<div class="raw">{_h.escape(cap['ua_raw'])}</div>
<p style="margin-top:18px"><a href="/">→ Ver el panel de control con todas las capturas</a></p>
</div></body></html>"""


# ===========================================================================
#  PANEL DE CONTROL  (shell HTML + JS que consume /api/data en vivo)
# ===========================================================================
PAGINA_PANEL = r"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Panel · Capturas de User-Agent</title>
<style>
 :root{--bg:#0d1117;--card:#161b22;--line:#30363d;--txt:#e6edf3;--mut:#8b949e;
        --cy:#39d0d8;--gr:#3fb950;--ye:#d29922;--rd:#f85149;--bl:#58a6ff;--mg:#bc8cff;}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--txt);
   font:14px/1.55 -apple-system,Segoe UI,Roboto,Arial,sans-serif}
 header{padding:22px 26px;background:linear-gradient(135deg,#0d1117,#132235);
   border-bottom:2px solid var(--cy);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
 header h1{margin:0;font-size:20px} header .live{color:var(--gr);font-size:13px}
 header .live b{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--gr);
   margin-right:6px;animation:pp 1.4s infinite}
 @keyframes pp{0%,100%{opacity:1}50%{opacity:.3}}
 main{max-width:1150px;margin:0 auto;padding:22px}
 .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:20px}
 .kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
 .kpi .n{font-size:30px;font-weight:800} .kpi .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 .kpi.c1 .n{color:var(--cy)} .kpi.c2 .n{color:var(--bl)} .kpi.c3 .n{color:var(--mg)} .kpi.c4 .n{color:var(--gr)}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:20px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
 .card h2{margin:0 0 14px;font-size:14px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
 .bar{margin-bottom:9px} .bar .top{display:flex;justify-content:space-between;font-size:13px;margin-bottom:3px}
 .bar .track{height:9px;background:#0b0f14;border-radius:6px;overflow:hidden}
 .bar .fill{height:100%;border-radius:6px;background:linear-gradient(90deg,var(--cy),var(--bl))}
 .card.cso .fill{background:linear-gradient(90deg,var(--gr),#2ea043)}
 .card.cdev .fill{background:linear-gradient(90deg,var(--mg),#8957e5)}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:8px 9px;border-bottom:1px solid var(--line);white-space:nowrap}
 th{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;background:var(--card)}
 td.raw{color:var(--mut);font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis}
 tr:hover td{background:#1c2330}
 .tag{padding:1px 8px;border-radius:20px;font-size:11px;font-weight:700}
 .tag.bot{background:rgba(188,140,255,.15);color:var(--mg)}
 .tag.movil{background:rgba(88,166,255,.15);color:var(--bl)}
 .tag.escritorio{background:rgba(57,208,216,.15);color:var(--cy)}
 .tag.tablet{background:rgba(210,153,34,.15);color:var(--ye)}
 .tabla-wrap{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 10px 10px;max-height:460px;overflow:auto}
 .vacio{color:var(--mut);text-align:center;padding:40px}
 code{color:var(--cy)}
</style></head><body>
<header>
  <h1>📡 Capturas de User-Agent</h1>
  <div class="live"><b></b>En vivo · se actualiza cada 2 s</div>
</header>
<main>
  <div class="kpis">
    <div class="kpi c1"><div class="n" id="k-total">0</div><div class="l">Peticiones</div></div>
    <div class="kpi c2"><div class="n" id="k-ips">0</div><div class="l">IPs unicas</div></div>
    <div class="kpi c3"><div class="n" id="k-bots">0</div><div class="l">Bots / tools</div></div>
    <div class="kpi c4"><div class="n" id="k-nav">—</div><div class="l">Navegador top</div></div>
  </div>
  <div class="grid">
    <div class="card cnav"><h2>Navegadores</h2><div id="g-nav"></div></div>
    <div class="card cso"><h2>Sistemas operativos</h2><div id="g-so"></div></div>
    <div class="card cdev"><h2>Dispositivos</h2><div id="g-dev"></div></div>
  </div>
  <div class="tabla-wrap">
    <table><thead><tr>
      <th>Hora</th><th>IP</th><th>Metodo</th><th>Ruta</th><th>Tipo</th>
      <th>Navegador</th><th>Sistema</th><th>User-Agent (raw)</th>
    </tr></thead><tbody id="filas">
      <tr><td colspan="8" class="vacio">Esperando peticiones… prueba:
      <code>curl http://localhost:PUERTO/test</code></td></tr>
    </tbody></table>
  </div>
</main>
<script>
const esc = s => (s||"").replace(/[&<>"]/g, m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[m]));
function barras(cont, obj, maxItems=6){
  const el = document.getElementById(cont);
  const entradas = Object.entries(obj||{}).slice(0,maxItems);
  const max = Math.max(1, ...entradas.map(e=>e[1]));
  if(!entradas.length){ el.innerHTML='<div style="color:#8b949e">Sin datos todavia</div>'; return; }
  el.innerHTML = entradas.map(([k,v])=>`
    <div class="bar"><div class="top"><span>${esc(k)}</span><span>${v}</span></div>
    <div class="track"><div class="fill" style="width:${Math.round(v/max*100)}%"></div></div></div>`).join("");
}
async function refrescar(){
  try{
    const d = await (await fetch("/api/data")).json();
    document.getElementById("k-total").textContent = d.total;
    document.getElementById("k-ips").textContent = d.ips_unicas;
    document.getElementById("k-bots").textContent = d.bots;
    const navTop = Object.keys(d.navegadores||{})[0] || "—";
    document.getElementById("k-nav").textContent = navTop;
    barras("g-nav", d.navegadores);
    barras("g-so", d.sistemas);
    barras("g-dev", d.dispositivos);
    const tb = document.getElementById("filas");
    if(!d.capturas.length) return;
    tb.innerHTML = d.capturas.map(c=>{
      const a=c.ua, t=a.bot?"bot":a.tipo;
      return `<tr>
        <td>${esc(c.hora.split(" ")[1]||c.hora)}</td>
        <td>${esc(c.ip)}</td>
        <td>${esc(c.metodo)}</td>
        <td>${esc(c.ruta)}</td>
        <td><span class="tag ${t}">${esc(t)}</span></td>
        <td><b>${esc(a.navegador)} ${esc(a.version)}</b></td>
        <td>${esc(a.so)}</td>
        <td class="raw" title="${esc(c.ua_raw)}">${esc(c.ua_raw)}</td>
      </tr>`;
    }).join("");
  }catch(e){ /* reintenta en el siguiente ciclo */ }
}
refrescar(); setInterval(refrescar, 2000);
</script>
</body></html>"""


# ===========================================================================
#  MAIN
# ===========================================================================
def main():
    global ALMACEN, USAR_COLOR
    p = argparse.ArgumentParser(
        description="Servidor HTTP que captura y analiza el User-Agent de las peticiones.",
        epilog="Ejemplo: python servidor_ua.py --puerto 8080")
    p.add_argument("--host", default="127.0.0.1",
                   help="interfaz de escucha (0.0.0.0 para toda la red). Por defecto 127.0.0.1")
    p.add_argument("--puerto", type=int, default=8080, help="puerto (por defecto 8080)")
    p.add_argument("--datos", default="capturas_ua.json",
                   help="archivo JSON donde persistir las capturas")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()

    _habilitar_terminal()
    if args.no_color:
        USAR_COLOR = False
    ALMACEN = Almacen(args.datos)

    panel = PAGINA_PANEL.replace("localhost:PUERTO", f"localhost:{args.puerto}")
    globals()["PAGINA_PANEL"] = panel

    servidor = ThreadingHTTPServer((args.host, args.puerto), Handler)
    print(c("\n╔" + "═" * 58 + "╗", C.CYAN))
    print(c("║", C.CYAN) + c("   Servidor de captura de User-Agent  ·  ACTIVO".ljust(58), C.BOLD + C.GREEN) + c("║", C.CYAN))
    print(c("╚" + "═" * 58 + "╝", C.CYAN))
    print(f"  {c('Panel de control:', C.BOLD)} {c(f'http://localhost:{args.puerto}/', C.CYAN)}")
    print(f"  {c('API JSON:', C.BOLD)}         {c(f'http://localhost:{args.puerto}/api/data', C.CYAN)}")
    print(f"  {c('Escuchando en:', C.BOLD)}    {args.host}:{args.puerto}")
    print(f"  {c('Guardando en:', C.BOLD)}     {os.path.abspath(args.datos)}")
    print(f"  {c('Capturas previas:', C.BOLD)} {len(ALMACEN.capturas)}")
    print(c("  Pulsa Ctrl+C para detener.\n", C.DIM))
    print(c("  " + "─" * 60, C.GREY))
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print(c("\n\n  Servidor detenido. Capturas totales: "
                + str(len(ALMACEN.capturas)), C.YELLOW))
        print(c(f"  Datos guardados en: {os.path.abspath(args.datos)}\n", C.DIM))

if __name__ == "__main__":
    main()
