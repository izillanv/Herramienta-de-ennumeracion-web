#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
  enumeracion.py  -  Herramienta de enumeracion PASIVA y ACTIVA
===============================================================================
  Autor : Izan Villalba
  Tipo  : Herramienta de reconocimiento / footprinting

  ENUMERACION PASIVA  (no se "ataca" al objetivo, se usa informacion publica):
      - WHOIS            -> registrador, fechas, nameservers, contactos
      - Registros DNS    -> A, AAAA, MX, NS, TXT, CNAME, SOA
      - crt.sh           -> subdominios via Certificate Transparency
      - robots.txt       -> rutas que el objetivo "pide" no indexar

  ENUMERACION ACTIVA  (se envian paquetes directamente al objetivo):
      - Escaneo de puertos TCP (connect scan) + captura de banners
      - Fingerprint HTTP (cabecera Server, title, tecnologias)
      - Fuerza bruta de subdominios por resolucion DNS

  SALIDA: consola con colores + informe HTML opcional (--html).

  Solo libreria estandar de Python 3. No requiere instalar nada.

  AVISO LEGAL: usar unicamente contra sistemas propios o con autorizacion
  expresa por escrito. El reconocimiento no autorizado puede ser ilegal.
===============================================================================
"""

import argparse
import concurrent.futures
import html
import json
import os
import random
import socket
import ssl
import struct
import sys
import urllib.request
import urllib.parse
from datetime import datetime

# ---------------------------------------------------------------------------
#  Estilo de consola (colores ANSI). Se desactiva solo si no hay soporte.
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"; GREY = "\033[90m"
    BG_BLUE = "\033[44m"

USAR_COLOR = True

def _habilitar_terminal():
    """Activa colores ANSI en Windows 10+ y detecta si hay terminal."""
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

def c(texto, color):
    return f"{color}{texto}{C.RESET}" if USAR_COLOR else str(texto)

def banner():
    txt = r"""
  ____  _____ ____ ___  _   _    ____  _____ ____  _   _ _____ ___
 |  _ \| ____/ ___/ _ \| \ | |  |  _ \| ____/ ___|| \ | |  ___/ _ \
 | |_) |  _|| |  | | | |  \| |  | |_) |  _|| |    |  \| | |_ | | | |
 |  _ <| |__| |__| |_| | |\  |  |  _ <| |__| |___ | |\  |  _|| |_| |
 |_| \_\_____\____\___/|_| \_|  |_| \_\_____\____||_| \_|_|   \___/ """
    print(c(txt, C.CYAN))
    print(c("        Enumeracion pasiva + activa  ·  solo stdlib\n", C.DIM))

def titulo(t):
    linea = "=" * 72
    print("\n" + c(linea, C.BLUE))
    print(c(f"  {t}", C.BOLD + C.CYAN))
    print(c(linea, C.BLUE))

def sub(t):
    print("\n" + c(f"── {t} " + "─" * max(0, 66 - len(t)), C.MAGENTA))

def kv(k, v, color=C.GREEN):
    print(f"  {c(k + ':', C.BOLD):<28} {c(v, color)}")

def ok(m):   print(f"  {c('[+]', C.GREEN)} {m}")
def warn(m): print(f"  {c('[!]', C.YELLOW)} {m}")
def err(m):  print(f"  {c('[-]', C.RED)} {m}")
def info(m): print(f"  {c('[*]', C.BLUE)} {m}")

def tabla(cabeceras, filas, colores=None):
    """Imprime una tabla ASCII alineada."""
    if not filas:
        print(c("  (sin resultados)", C.DIM)); return
    anchos = [len(h) for h in cabeceras]
    for fila in filas:
        for i, celda in enumerate(fila):
            anchos[i] = max(anchos[i], len(str(celda)))
    sep = "  +" + "+".join("-" * (a + 2) for a in anchos) + "+"
    cab = "  |" + "|".join(" " + c(h.ljust(anchos[i]), C.BOLD) + " "
                           for i, h in enumerate(cabeceras)) + "|"
    print(c(sep, C.GREY)); print(cab); print(c(sep, C.GREY))
    for fila in filas:
        celdas = []
        for i, celda in enumerate(fila):
            txt = str(celda).ljust(anchos[i])
            if colores and colores(fila):
                txt = c(txt, colores(fila))
            celdas.append(" " + txt + " ")
        print("  |" + "|".join(celdas) + "|")
    print(c(sep, C.GREY))


# ===========================================================================
#  RESOLUCION DNS  (consulta UDP cruda al servidor 8.8.8.8, con respaldo)
# ===========================================================================
TIPOS_DNS = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}

def _codificar_nombre(nombre):
    salida = b""
    for parte in nombre.rstrip(".").split("."):
        salida += bytes([len(parte)]) + parte.encode()
    return salida + b"\x00"

def _leer_nombre(data, offset):
    """Lee un nombre DNS gestionando la compresion por punteros."""
    etiquetas = []
    salto = None
    while True:
        longitud = data[offset]
        if longitud == 0:
            offset += 1
            break
        if longitud & 0xC0 == 0xC0:               # puntero de compresion
            puntero = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if salto is None:
                salto = offset + 2
            offset = puntero
            continue
        offset += 1
        etiquetas.append(data[offset:offset + longitud].decode(errors="replace"))
        offset += longitud
    return ".".join(etiquetas), (salto if salto is not None else offset)

def consulta_dns(nombre, tipo="A", servidor="8.8.8.8", timeout=4.0):
    """Devuelve una lista de valores para el tipo de registro pedido."""
    qtype = TIPOS_DNS.get(tipo.upper(), 1)
    tid = random.randint(0, 0xFFFF)
    cabecera = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    pregunta = _codificar_nombre(nombre) + struct.pack("!HH", qtype, 1)
    paquete = cabecera + pregunta

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(paquete, (servidor, 53))
        data, _ = s.recvfrom(4096)
    except Exception:
        return _consulta_dns_respaldo(nombre, tipo)
    finally:
        s.close()

    _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):                            # saltar la pregunta
        _, offset = _leer_nombre(data, offset)
        offset += 4

    resultados = []
    for _ in range(an):
        _, offset = _leer_nombre(data, offset)
        rtipo, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtipo == 1:                             # A
            resultados.append(socket.inet_ntoa(rdata))
        elif rtipo == 28:                          # AAAA
            resultados.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtipo in (2, 5):                      # NS / CNAME
            resultados.append(_leer_nombre(data, offset)[0])
        elif rtipo == 15:                          # MX
            pref = struct.unpack("!H", rdata[:2])[0]
            resultados.append(f"{pref} {_leer_nombre(data, offset + 2)[0]}")
        elif rtipo == 16:                          # TXT
            i, partes = 0, []
            while i < len(rdata):
                ln = rdata[i]; partes.append(rdata[i + 1:i + 1 + ln].decode(errors="replace")); i += 1 + ln
            resultados.append("".join(partes))
        elif rtipo == 6:                           # SOA
            mname, o2 = _leer_nombre(data, offset)
            rname, _ = _leer_nombre(data, o2)
            resultados.append(f"{mname} {rname}")
        offset += rdlen
    return resultados

def _consulta_dns_respaldo(nombre, tipo):
    """Si el UDP crudo falla (p.ej. red restringida), usa getaddrinfo."""
    try:
        if tipo.upper() == "A":
            return sorted({x[4][0] for x in socket.getaddrinfo(nombre, None, socket.AF_INET)})
        if tipo.upper() == "AAAA":
            return sorted({x[4][0] for x in socket.getaddrinfo(nombre, None, socket.AF_INET6)})
    except Exception:
        return []
    return []


# ===========================================================================
#  WHOIS  (protocolo whois sobre TCP 43, siguiendo referencias de IANA)
# ===========================================================================
def _whois_crudo(servidor, consulta, timeout=8.0):
    try:
        s = socket.create_connection((servidor, 43), timeout=timeout)
        s.sendall((consulta + "\r\n").encode())
        datos = b""
        while True:
            trozo = s.recv(4096)
            if not trozo:
                break
            datos += trozo
        s.close()
        return datos.decode(errors="replace")
    except Exception as e:
        return f"__ERROR__ {e}"

def whois(dominio):
    """WHOIS en cadena: IANA -> servidor del TLD -> servidor del registrador."""
    tld = dominio.rsplit(".", 1)[-1]
    raiz = _whois_crudo("whois.iana.org", tld)
    servidor_tld = None
    for linea in raiz.splitlines():
        if linea.lower().startswith("whois:"):
            servidor_tld = linea.split(":", 1)[1].strip(); break
    if not servidor_tld:
        return raiz, None
    texto = _whois_crudo(servidor_tld, dominio)
    # Seguir referencia al WHOIS del registrador si existe
    for linea in texto.splitlines():
        bajo = linea.lower()
        if "registrar whois server:" in bajo or "whois server:" in bajo:
            ref = linea.split(":", 1)[1].strip()
            if ref and ref != servidor_tld:
                extra = _whois_crudo(ref, dominio)
                if not extra.startswith("__ERROR__"):
                    texto += "\n\n;; --- Registrar WHOIS (" + ref + ") ---\n" + extra
            break
    return texto, servidor_tld

def extraer_whois(texto):
    """Saca los campos mas interesantes del volcado WHOIS."""
    campos = {
        "Registrador": ["registrar:"],
        "Creado": ["creation date:", "created:", "registered on:"],
        "Expira": ["registry expiry date:", "expiry date:", "expiration date:", "paid-till:"],
        "Actualizado": ["updated date:", "last updated:", "changed:"],
        "Estado": ["domain status:", "status:"],
        "Organizacion": ["registrant organization:", "org:", "organization:"],
        "Pais": ["registrant country:", "country:"],
        "Nameservers": ["name server:", "nserver:"],
    }
    salida = {}
    for linea in texto.splitlines():
        bajo = linea.lower().strip()
        for nombre, claves in campos.items():
            for clave in claves:
                if bajo.startswith(clave):
                    valor = linea.split(":", 1)[1].strip()
                    if not valor:
                        continue
                    if nombre in ("Nameservers", "Estado"):
                        salida.setdefault(nombre, [])
                        if valor not in salida[nombre]:
                            salida[nombre].append(valor)
                    else:
                        salida.setdefault(nombre, valor)
    return salida


# ===========================================================================
#  crt.sh  (subdominios via Certificate Transparency - PASIVO)
# ===========================================================================
def crtsh_subdominios(dominio, timeout=20):
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(dominio)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "enum-script/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            datos = json.loads(r.read().decode(errors="replace"))
    except Exception as e:
        return [], str(e)
    nombres = set()
    for fila in datos:
        for n in str(fila.get("name_value", "")).split("\n"):
            n = n.strip().lstrip("*.").lower()
            if n.endswith(dominio) and " " not in n:
                nombres.add(n)
    return sorted(nombres), None


# ===========================================================================
#  robots.txt + fingerprint HTTP
# ===========================================================================
def _peticion_http(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (enum-script)"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # permite TLS mal configurado en pruebas
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)

def robots_txt(host):
    for esquema in ("https", "http"):
        try:
            r = _peticion_http(f"{esquema}://{host}/robots.txt")
            cuerpo = r.read(8192).decode(errors="replace")
            if r.status == 200 and ("User-agent" in cuerpo or "Disallow" in cuerpo):
                return cuerpo, f"{esquema}://{host}/robots.txt"
        except Exception:
            continue
    return None, None

def fingerprint_http(host):
    for esquema in ("https", "http"):
        try:
            r = _peticion_http(f"{esquema}://{host}")
            cuerpo = r.read(65536).decode(errors="replace")
            titulo_pag = None
            bajo = cuerpo.lower()
            if "<title" in bajo:
                ini = bajo.find("<title"); ini = cuerpo.find(">", ini) + 1
                fin = bajo.find("</title>", ini)
                if fin > ini:
                    titulo_pag = " ".join(cuerpo[ini:fin].split())[:120]
            return {
                "url": f"{esquema}://{host}",
                "status": r.status,
                "server": r.headers.get("Server", "-"),
                "powered": r.headers.get("X-Powered-By", "-"),
                "titulo": titulo_pag or "-",
            }
        except Exception:
            continue
    return None


# ===========================================================================
#  ESCANEO DE PUERTOS (connect scan) + BANNERS
# ===========================================================================
PUERTOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3000: "Dev",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP-alt", 8080: "HTTP-proxy", 8443: "HTTPS-alt", 9200: "Elastic",
    27017: "MongoDB",
}

def _grab_banner(sock, puerto):
    try:
        sock.settimeout(2.0)
        if puerto in (80, 8080, 8000, 3000):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        datos = sock.recv(256)
        return " ".join(datos.decode(errors="replace").split())[:100]
    except Exception:
        return ""

def escanear_puerto(host, puerto, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, puerto)) == 0:
            banner = _grab_banner(s, puerto)
            s.close()
            return puerto, PUERTOS_COMUNES.get(puerto, "?"), banner
        s.close()
    except Exception:
        pass
    return None

def escanear_puertos(host, puertos, timeout=1.0, hilos=100):
    abiertos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as ex:
        futuros = {ex.submit(escanear_puerto, host, p, timeout): p for p in puertos}
        for f in concurrent.futures.as_completed(futuros):
            r = f.result()
            if r:
                abiertos.append(r)
    return sorted(abiertos)


# ===========================================================================
#  FUERZA BRUTA DE SUBDOMINIOS (activo: resuelve cada candidato por DNS)
# ===========================================================================
PALABRAS_SUBDOMINIOS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "vpn", "remote", "portal", "admin", "test", "dev", "staging",
    "api", "app", "cdn", "static", "assets", "blog", "shop", "tienda",
    "intranet", "cloud", "git", "gitlab", "jenkins", "jira", "proxy",
    "gateway", "server", "db", "database", "backup", "monitor", "zabbix",
    "grafana", "kibana", "owa", "autodiscover", "m", "mobile", "beta",
    "demo", "soporte", "support", "login", "sso", "auth", "secure",
]

def subdominios_activos(dominio, palabras, hilos=50):
    def resolver(sub):
        fqdn = f"{sub}.{dominio}"
        ips = consulta_dns(fqdn, "A")
        return (fqdn, ips) if ips else None
    encontrados = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as ex:
        for r in ex.map(resolver, palabras):
            if r:
                encontrados.append(r)
    return sorted(encontrados)


# ===========================================================================
#  INFORME HTML
# ===========================================================================
def generar_html(objetivo, secciones, ruta):
    def esc(x):
        return html.escape(str(x))
    bloques = ""
    for titulo_sec, contenido in secciones:
        bloques += f'<section><h2>{esc(titulo_sec)}</h2>{contenido}</section>\n'
    plantilla = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de enumeracion · {esc(objetivo)}</title>
<style>
 :root{{--bg:#0d1117;--card:#161b22;--line:#30363d;--txt:#e6edf3;--mut:#8b949e;
        --cy:#39d0d8;--gr:#3fb950;--ye:#d29922;--rd:#f85149;--bl:#58a6ff;}}
 *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--txt);
   font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
 header{{padding:32px 24px;background:linear-gradient(135deg,#0d1117,#132235);
   border-bottom:2px solid var(--cy)}}
 header h1{{margin:0;font-size:24px}} header .obj{{color:var(--cy);font-weight:700}}
 header .meta{{color:var(--mut);font-size:13px;margin-top:6px}}
 main{{max-width:1000px;margin:0 auto;padding:24px}}
 section{{background:var(--card);border:1px solid var(--line);border-radius:12px;
   padding:20px 24px;margin:18px 0}}
 h2{{margin:0 0 14px;font-size:18px;color:var(--bl);border-bottom:1px solid var(--line);
   padding-bottom:8px}}
 table{{width:100%;border-collapse:collapse;font-size:14px}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
   vertical-align:top;word-break:break-word}}
 th{{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
 tr:hover td{{background:#1c2330}}
 .kv{{color:var(--mut)}} .v{{color:var(--gr)}}
 pre{{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:14px;
   overflow:auto;font-size:12.5px;color:#c9d1d9;max-height:360px}}
 .tag{{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:700}}
 .open{{background:rgba(63,185,80,.15);color:var(--gr)}}
 code{{color:var(--cy)}} footer{{color:var(--mut);text-align:center;padding:24px;font-size:12px}}
</style></head><body>
<header><h1>Informe de enumeracion — <span class="obj">{esc(objetivo)}</span></h1>
<div class="meta">Generado el {datetime.now():%d/%m/%Y %H:%M:%S} · enumeracion.py</div></header>
<main>{bloques}</main>
<footer>Herramienta de reconocimiento · usar solo con autorizacion</footer>
</body></html>"""
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(plantilla)
    return ruta

def _tabla_html(cab, filas):
    if not filas:
        return '<p class="kv">(sin resultados)</p>'
    h = "".join(f"<th>{html.escape(x)}</th>" for x in cab)
    cuerpo = ""
    for fila in filas:
        cuerpo += "<tr>" + "".join(f"<td>{html.escape(str(x))}</td>" for x in fila) + "</tr>"
    return f"<table><thead><tr>{h}</tr></thead><tbody>{cuerpo}</tbody></table>"


# ===========================================================================
#  ORQUESTACION
# ===========================================================================
def resolver_objetivo(objetivo):
    """Separa host/dominio e IP. Devuelve (es_dominio, ip)."""
    try:
        socket.inet_aton(objetivo)
        return False, objetivo                 # ya es una IP
    except OSError:
        ips = consulta_dns(objetivo, "A")
        return True, (ips[0] if ips else None)

def fase_pasiva(objetivo, es_dominio, secciones_html):
    titulo("FASE PASIVA  (informacion publica, sin tocar el objetivo)")

    # --- DNS ---
    if es_dominio:
        sub("Registros DNS")
        filas_dns = []
        for tipo in ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"):
            for valor in consulta_dns(objetivo, tipo):
                filas_dns.append([tipo, valor])
                kv(tipo, valor, C.GREEN)
        if not filas_dns:
            warn("No se obtuvieron registros DNS (red restringida?)")
        secciones_html.append(("Registros DNS", _tabla_html(["Tipo", "Valor"], filas_dns)))

        # --- WHOIS ---
        sub("WHOIS")
        texto_whois, srv = whois(objetivo)
        if texto_whois.startswith("__ERROR__"):
            err("WHOIS no disponible: " + texto_whois)
            secciones_html.append(("WHOIS", '<p class="kv">No disponible</p>'))
        else:
            info(f"Servidor WHOIS del TLD: {srv}")
            campos = extraer_whois(texto_whois)
            filas_w = []
            for k, v in campos.items():
                v2 = ", ".join(v) if isinstance(v, list) else v
                kv(k, v2, C.CYAN)
                filas_w.append([k, v2])
            whois_html = _tabla_html(["Campo", "Valor"], filas_w)
            whois_html += f"<details><summary>Volcado WHOIS completo</summary><pre>{html.escape(texto_whois[:12000])}</pre></details>"
            secciones_html.append(("WHOIS", whois_html))

        # --- crt.sh ---
        sub("Subdominios en Certificate Transparency (crt.sh)")
        subs, e = crtsh_subdominios(objetivo)
        if e:
            err("crt.sh no disponible: " + e)
        else:
            ok(f"{len(subs)} subdominios unicos encontrados")
            for s in subs[:40]:
                print("    " + c(s, C.GREEN))
            if len(subs) > 40:
                info(f"... y {len(subs) - 40} mas (ver informe HTML)")
        secciones_html.append(("Subdominios (crt.sh)",
                               _tabla_html(["Subdominio"], [[s] for s in subs])))

    # --- robots.txt ---
    sub("robots.txt")
    host = objetivo
    robots, url_r = robots_txt(host)
    if robots:
        ok(f"Encontrado en {url_r}")
        for linea in robots.splitlines()[:25]:
            if linea.strip():
                print("    " + c(linea, C.DIM))
        secciones_html.append(("robots.txt",
                               f"<p class='kv'>{html.escape(url_r)}</p><pre>{html.escape(robots[:6000])}</pre>"))
    else:
        warn("Sin robots.txt accesible")

def fase_activa(objetivo, ip, es_dominio, puertos, timeout, secciones_html):
    titulo("FASE ACTIVA  (se envian paquetes directamente al objetivo)")
    if not ip:
        err("No se pudo resolver una IP; se omite el escaneo de puertos.")
    else:
        info(f"Objetivo resuelto a IP: {c(ip, C.BOLD)}")
        sub(f"Escaneo de puertos TCP  ({len(puertos)} puertos)")
        abiertos = escanear_puertos(ip, puertos, timeout=timeout)
        if abiertos:
            ok(f"{len(abiertos)} puertos abiertos")
            tabla(["PUERTO", "SERVICIO", "BANNER"],
                  [[f"{p}/tcp", srv, (ban or '-')] for p, srv, ban in abiertos],
                  colores=lambda f: C.GREEN)
        else:
            warn("No se detectaron puertos abiertos (firewall / host filtrado)")
        secciones_html.append(("Puertos abiertos",
            _tabla_html(["Puerto", "Servicio", "Banner"],
                        [[f"{p}/tcp", srv, ban or "-"] for p, srv, ban in abiertos])))

    # --- Fingerprint HTTP ---
    sub("Fingerprint HTTP")
    fp = fingerprint_http(objetivo)
    if fp:
        kv("URL", fp["url"], C.CYAN)
        kv("Codigo HTTP", str(fp["status"]))
        kv("Server", fp["server"], C.YELLOW)
        kv("X-Powered-By", fp["powered"], C.YELLOW)
        kv("Title", fp["titulo"])
        secciones_html.append(("Fingerprint HTTP", _tabla_html(
            ["Campo", "Valor"],
            [["URL", fp["url"]], ["Codigo", fp["status"]], ["Server", fp["server"]],
             ["X-Powered-By", fp["powered"]], ["Title", fp["titulo"]]])))
    else:
        warn("Sin servicio HTTP/HTTPS accesible")

    # --- Fuerza bruta de subdominios ---
    if es_dominio:
        sub(f"Fuerza bruta de subdominios  ({len(PALABRAS_SUBDOMINIOS)} candidatos)")
        encontrados = subdominios_activos(objetivo, PALABRAS_SUBDOMINIOS)
        if encontrados:
            ok(f"{len(encontrados)} subdominios activos")
            tabla(["SUBDOMINIO", "IPs"],
                  [[fqdn, ", ".join(ips)] for fqdn, ips in encontrados])
        else:
            warn("Ningun subdominio de la lista resolvio")
        secciones_html.append(("Subdominios activos (fuerza bruta DNS)",
            _tabla_html(["Subdominio", "IPs"],
                        [[f, ", ".join(ips)] for f, ips in encontrados])))

# ===========================================================================
#  MODO INTERACTIVO  (el usuario elige y confirma cada paso)
# ===========================================================================
def _entrada(texto, defecto=""):
    """input() con color y gestion de Ctrl+C / EOF."""
    try:
        r = input(c(texto, C.BOLD + C.CYAN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "__SALIR__"
    return r or defecto

def _confirmar(texto, defecto=False):
    r = _entrada(f"  {texto}" + (" [S/n] " if defecto else " [s/N] "))
    if r == "__SALIR__":
        return False
    if not r:
        return defecto
    return r.lower()[0] in ("s", "y")

def _pausa():
    _entrada(c("\n  ↵  Pulsa Enter para volver al menu...", C.DIM))

def _menu(titulo_menu, opciones):
    """Dibuja un menu 'vistoso' y devuelve la tecla elegida.
    opciones: lista de (tecla, etiqueta, descripcion)."""
    print()
    print(c("  ╭─ ", C.CYAN) + c(titulo_menu, C.BOLD + C.CYAN)
          + c(" " + "─" * max(4, 54 - len(titulo_menu)) + "╮", C.CYAN))
    for tecla, etiqueta, desc in opciones:
        linea = ("  " + c("│", C.CYAN) + "   " + c(f"[{tecla}]", C.GREEN + C.BOLD)
                 + " " + c(etiqueta, C.BOLD))
        if desc:
            linea += c("  ·  " + desc, C.DIM)
        print(linea)
    print(c("  ╰" + "─" * 58 + "╯", C.CYAN))
    return _entrada("\n  ➤  Elige una opcion: ")

def _estado_barra(st):
    """Barra de estado: que sabemos del objetivo hasta ahora."""
    partes = [
        c("Objetivo: ", C.DIM) + c(st["objetivo"], C.YELLOW + C.BOLD),
        c("IP: ", C.DIM) + c(st["ip"] or "—", C.GREEN),
        c("Subdominios: ", C.DIM) + c(str(len(st["subdominios"])), C.CYAN),
        c("Bloques informe: ", C.DIM) + c(str(len(st["secciones_html"])), C.MAGENTA),
    ]
    print("\n  " + c("▌ ", C.CYAN) + "    ".join(partes))

def _parse_puertos(texto):
    """Convierte '80,443,8000-8010' en una lista de puertos."""
    puertos = []
    for trozo in texto.replace(" ", "").split(","):
        if not trozo:
            continue
        if "-" in trozo:
            a, b = trozo.split("-"); puertos += list(range(int(a), int(b) + 1))
        else:
            puertos.append(int(trozo))
    return puertos

def _slug(texto):
    return "".join(ch if ch.isalnum() else "_" for ch in texto)

def _nuevo_estado(objetivo):
    objetivo = objetivo.strip().replace("https://", "").replace("http://", "").strip("/")
    return {"objetivo": objetivo, "ip": None, "es_dominio": True,
            "subdominios": [], "secciones_html": []}

def _resolver_estado(st):
    es_dom, ip = resolver_objetivo(st["objetivo"])
    st["es_dominio"], st["ip"] = es_dom, ip
    if ip:
        ok(f"{st['objetivo']} resuelve a {c(ip, C.BOLD)}")
    else:
        warn("No se pudo resolver la IP (podras reintentarlo).")

# ---- Recolectores (cada uno recoge un dato y lo guarda en el informe) ----
def _recoger_dns(st):
    sub("Registros DNS")
    filas = []
    for tipo in ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"):
        for valor in consulta_dns(st["objetivo"], tipo):
            filas.append([tipo, valor]); kv(tipo, valor, C.GREEN)
    if not filas:
        warn("Sin registros DNS (red restringida?).")
    st["secciones_html"].append(("Registros DNS", _tabla_html(["Tipo", "Valor"], filas)))

def _recoger_whois(st):
    sub("WHOIS")
    texto, srv = whois(st["objetivo"])
    if texto.startswith("__ERROR__"):
        err("WHOIS no disponible.")
        return
    info(f"Servidor WHOIS del TLD: {srv}")
    campos = extraer_whois(texto); filas = []
    for k, v in campos.items():
        v2 = ", ".join(v) if isinstance(v, list) else v
        kv(k, v2, C.CYAN); filas.append([k, v2])
    st["secciones_html"].append(("WHOIS", _tabla_html(["Campo", "Valor"], filas)))

def _recoger_crtsh(st):
    sub("Subdominios en Certificate Transparency (crt.sh)")
    subs, e = crtsh_subdominios(st["objetivo"])
    if e:
        err("crt.sh no disponible: " + e); return
    ok(f"{len(subs)} subdominios unicos encontrados")
    for s in subs:
        if s not in st["subdominios"]:
            st["subdominios"].append(s)
    for s in subs[:40]:
        print("    " + c(s, C.GREEN))
    if len(subs) > 40:
        info(f"... y {len(subs) - 40} mas")
    st["secciones_html"].append(("Subdominios (crt.sh)",
                                 _tabla_html(["Subdominio"], [[s] for s in subs])))

def _recoger_robots(st):
    sub("robots.txt")
    robots, url_r = robots_txt(st["objetivo"])
    if robots:
        ok(f"Encontrado en {url_r}")
        for linea in robots.splitlines()[:25]:
            if linea.strip():
                print("    " + c(linea, C.DIM))
        st["secciones_html"].append(("robots.txt",
            f"<p>{url_r}</p><pre>{html.escape(robots[:6000])}</pre>"))
    else:
        warn("Sin robots.txt accesible.")

def _recoger_fingerprint(st):
    sub("Fingerprint HTTP")
    fp = fingerprint_http(st["objetivo"])
    if not fp:
        warn("Sin servicio HTTP/HTTPS accesible."); return
    kv("URL", fp["url"], C.CYAN); kv("Codigo HTTP", str(fp["status"]))
    kv("Server", fp["server"], C.YELLOW); kv("Title", fp["titulo"])
    st["secciones_html"].append(("Fingerprint HTTP", _tabla_html(["Campo", "Valor"],
        [["URL", fp["url"]], ["Codigo", fp["status"]], ["Server", fp["server"]],
         ["X-Powered-By", fp["powered"]], ["Title", fp["titulo"]]])))

def _recoger_subbrute(st):
    sub(f"Fuerza bruta de subdominios ({len(PALABRAS_SUBDOMINIOS)} candidatos)")
    encontrados = subdominios_activos(st["objetivo"], PALABRAS_SUBDOMINIOS)
    if encontrados:
        ok(f"{len(encontrados)} subdominios activos")
        tabla(["SUBDOMINIO", "IPs"], [[f, ", ".join(ips)] for f, ips in encontrados])
        for fqdn, _ in encontrados:
            if fqdn not in st["subdominios"]:
                st["subdominios"].append(fqdn)
    else:
        warn("Ningun subdominio de la lista resolvio.")
    st["secciones_html"].append(("Subdominios activos (fuerza bruta DNS)",
        _tabla_html(["Subdominio", "IPs"], [[f, ", ".join(ips)] for f, ips in encontrados])))

# ---- Helpers compartidos ----
def _escanear_y_guardar(st, puertos, timeout, etiqueta="Puertos abiertos"):
    """Escanea puertos, los muestra y los anade al informe. Devuelve la lista."""
    puertos = list(puertos)
    sub(f"Escaneo de puertos TCP ({len(puertos)} puertos)")
    abiertos = escanear_puertos(st["ip"], puertos, timeout=timeout)
    if abiertos:
        ok(f"{len(abiertos)} puertos abiertos")
        tabla(["PUERTO", "SERVICIO", "BANNER"],
              [[f"{p}/tcp", srv, (ban or '-')] for p, srv, ban in abiertos])
    else:
        warn("No se detectaron puertos abiertos.")
    st["secciones_html"].append((etiqueta,
        _tabla_html(["Puerto", "Servicio", "Banner"],
                    [[f"{p}/tcp", srv, ban or "-"] for p, srv, ban in abiertos])))
    return abiertos

def _informe_auto(st, prefijo="informe"):
    """Genera el informe con nombre por defecto (usado por los modos 'completo')."""
    if not st["secciones_html"]:
        warn("No se recogio nada, no se genera informe.")
        return
    nombre = f"{prefijo}_{_slug(st['objetivo'])}.html"
    ruta = generar_html(st["objetivo"], st["secciones_html"], nombre)
    titulo("INFORME")
    ok(f"Informe HTML guardado en: {c(os.path.abspath(ruta), C.CYAN)}")
    if os.name == "nt":
        info("Abrelo con doble clic o, en la terminal:  start " + nombre)
    else:
        info("Abrelo en el navegador: " + os.path.abspath(ruta))

# ---- Modos "completo" (una fase entera de un tiron + informe) ----
def _i_pasiva_completa(st):
    titulo("RECONOCIMIENTO PASIVO COMPLETO")
    info("Ejecuto DNS + WHOIS + crt.sh + robots.txt y genero el informe.")
    _recoger_dns(st)
    _recoger_whois(st)
    _recoger_crtsh(st)
    _recoger_robots(st)
    _informe_auto(st, "informe_pasivo")
    _pausa()

def _i_activa_completa(st, timeout):
    titulo("RECONOCIMIENTO ACTIVO COMPLETO")
    if not st["ip"]:
        _resolver_estado(st)
        if not st["ip"]:
            warn("Sin IP no se puede hacer la fase activa."); _pausa(); return
    print()
    if not _confirmar(f"Fase activa completa sobre {c(st['ip'], C.BOLD)}: escaneo de puertos comunes "
                      "+ fingerprint HTTP + fuerza bruta de subdominios.\n     Esto ENVIA trafico al "
                      "objetivo. ¿Continuar?", False):
        info("Reconocimiento activo cancelado por el usuario."); _pausa(); return
    _escanear_y_guardar(st, sorted(PUERTOS_COMUNES), timeout)
    _recoger_fingerprint(st)
    if st["es_dominio"]:
        _recoger_subbrute(st)
    _informe_auto(st, "informe_activo")
    _pausa()

# ---- Sub-flujos del menu (paso a paso) ----
def _i_pasiva(st):
    while True:
        op = _menu("FASE PASIVA · tu eliges que recoger", [
            ("1", "Todo", "DNS + WHOIS + crt.sh + robots"),
            ("2", "Registros DNS", ""),
            ("3", "WHOIS", ""),
            ("4", "Subdominios (crt.sh)", ""),
            ("5", "robots.txt", ""),
            ("0", "Volver", "")])
        if op in ("0", "__SALIR__"):
            return
        if op in ("1", "2"): _recoger_dns(st)
        if op in ("1", "3"): _recoger_whois(st)
        if op in ("1", "4"): _recoger_crtsh(st)
        if op in ("1", "5"): _recoger_robots(st)
        if op == "1":
            _pausa(); return
        if op not in ("2", "3", "4", "5"):
            warn("Opcion no valida.")
        _pausa()

def _i_activa(st, timeout):
    if not st["ip"]:
        if _confirmar("No hay IP resuelta. ¿Intento resolver de nuevo?", True):
            _resolver_estado(st)
        if not st["ip"]:
            warn("Sin IP no se puede escanear puertos."); _pausa(); return
    op = _menu("FASE ACTIVA · ¿que puertos escaneo?", [
        ("1", "Comunes", "rapido, ~31 puertos"),
        ("2", "1-1024", "puertos bien conocidos"),
        ("3", "Todos", "1-65535, lento"),
        ("4", "Personalizado", "ej: 80,443,3389"),
        ("0", "Volver", "")])
    if op in ("0", "__SALIR__"):
        return
    if op == "1":   puertos = sorted(PUERTOS_COMUNES)
    elif op == "2": puertos = list(range(1, 1025))
    elif op == "3": puertos = list(range(1, 65536))
    elif op == "4":
        s = _entrada("  Puertos (coma y/o rango): ")
        try:
            puertos = _parse_puertos(s)
        except ValueError:
            err("Formato no valido."); _pausa(); return
    else:
        warn("Opcion no valida."); _pausa(); return

    print()
    if not _confirmar(f"Vas a escanear {c(st['ip'], C.BOLD)} ({len(puertos)} puertos). "
                      "Esto ENVIA trafico al objetivo. ¿Continuar?", False):
        info("Escaneo cancelado por el usuario."); _pausa(); return

    _escanear_y_guardar(st, puertos, timeout)

    if _confirmar("¿Hago fingerprint HTTP del objetivo?", True):
        _recoger_fingerprint(st)
    if st["es_dominio"] and _confirmar("¿Fuerza bruta de subdominios?", False):
        _recoger_subbrute(st)
    _pausa()

def _i_subdominio(st, timeout):
    if not st["subdominios"]:
        warn("Aun no hay subdominios descubiertos. Lanza antes la fase pasiva (crt.sh).")
        _pausa(); return
    sub("Subdominios descubiertos")
    for i, s in enumerate(st["subdominios"], 1):
        print(f"    {c(f'[{i}]', C.CYAN)} {s}")
    sel = _entrada("\n  ¿Cual escaneo? (numero, varios con coma, o 'todos'): ")
    if sel in ("", "__SALIR__"):
        return
    if sel.lower() == "todos":
        elegidos = list(st["subdominios"])
    else:
        try:
            idx = [int(x) - 1 for x in sel.replace(" ", "").split(",")]
            elegidos = [st["subdominios"][i] for i in idx if 0 <= i < len(st["subdominios"])]
        except ValueError:
            err("Seleccion no valida."); _pausa(); return
    if not elegidos:
        warn("Nada seleccionado."); _pausa(); return
    if not _confirmar(f"Vas a escanear {len(elegidos)} subdominio(s). Esto ENVIA trafico. "
                      "¿Continuar?", False):
        info("Cancelado."); _pausa(); return
    for fqdn in elegidos:
        sub(f"Escaneo de {fqdn}")
        ips = consulta_dns(fqdn, "A")
        if not ips:
            warn(f"{fqdn} no resuelve."); continue
        ip = ips[0]; info(f"Resuelve a {c(ip, C.BOLD)}")
        abiertos = escanear_puertos(ip, sorted(PUERTOS_COMUNES), timeout=timeout)
        if abiertos:
            ok(f"{len(abiertos)} puertos abiertos")
            tabla(["PUERTO", "SERVICIO", "BANNER"],
                  [[f"{p}/tcp", srv, (ban or '-')] for p, srv, ban in abiertos])
        else:
            warn("Sin puertos abiertos.")
        st["secciones_html"].append((f"Puertos de {fqdn} ({ip})",
            _tabla_html(["Puerto", "Servicio", "Banner"],
                        [[f"{p}/tcp", srv, ban or "-"] for p, srv, ban in abiertos])))
    _pausa()

def _i_informe(st):
    if not st["secciones_html"]:
        warn("Todavia no has recogido nada. Lanza alguna fase primero.")
        _pausa(); return
    por_defecto = f"informe_{_slug(st['objetivo'])}.html"
    nombre = _entrada(f"  Nombre del archivo [{por_defecto}]: ", por_defecto)
    if nombre == "__SALIR__":
        return
    ruta = generar_html(st["objetivo"], st["secciones_html"], nombre)
    titulo("INFORME")
    ok(f"Informe HTML guardado en: {c(os.path.abspath(ruta), C.CYAN)}")
    info("Abrelo con doble clic o, en la terminal, con:  start " + nombre
         if os.name == "nt" else "Abrelo en el navegador: " + os.path.abspath(ruta))
    _pausa()

def modo_interactivo(objetivo_inicial=None, timeout=1.0):
    print(c("\n  ⚡  MODO INTERACTIVO  —  tu decides cada paso", C.BOLD + C.MAGENTA))
    print(c("     (eliges y confirmas cada accion)\n", C.DIM))
    objetivo = objetivo_inicial or _entrada("  Introduce el objetivo (dominio o IP): ")
    if not objetivo or objetivo == "__SALIR__":
        print(c("  Sin objetivo. Saliendo.\n", C.YELLOW)); return
    st = _nuevo_estado(objetivo)
    _resolver_estado(st)
    while True:
        _estado_barra(st)
        op = _menu("MENU PRINCIPAL", [
            ("1", "Reconocimiento PASIVO completo", "todo lo pasivo + informe"),
            ("2", "Reconocimiento ACTIVO completo", "todo lo activo + informe"),
            ("3", "Enumeracion PASIVA (elegir modulos)", "DNS · WHOIS · crt.sh · robots"),
            ("4", "Enumeracion ACTIVA (elegir puertos)", "puertos · banners · fingerprint"),
            ("5", "Escanear un SUBDOMINIO descubierto", "tu eliges cual"),
            ("6", "Generar INFORME HTML", ""),
            ("7", "Cambiar de objetivo", ""),
            ("0", "Salir", "")])
        if op in ("0", "__SALIR__"):
            print(c("\n  Hasta luego. Capturas en el informe si lo generaste.\n", C.GREEN + C.BOLD))
            return
        elif op == "1": _i_pasiva_completa(st)
        elif op == "2": _i_activa_completa(st, timeout)
        elif op == "3": _i_pasiva(st)
        elif op == "4": _i_activa(st, timeout)
        elif op == "5": _i_subdominio(st, timeout)
        elif op == "6": _i_informe(st)
        elif op == "7":
            nuevo = _entrada("  Nuevo objetivo: ")
            if nuevo and nuevo != "__SALIR__":
                st = _nuevo_estado(nuevo); _resolver_estado(st)
        else:
            warn("Opcion no valida.")


def main():
    p = argparse.ArgumentParser(
        description="Enumeracion pasiva y activa de un objetivo.",
        epilog="Ejemplos:\n"
               "  python enumeracion.py                    (modo interactivo, tu decides)\n"
               "  python enumeracion.py example.com --html informe.html\n"
               "  python enumeracion.py example.com -i     (interactivo con objetivo ya puesto)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("objetivo", nargs="?", help="dominio o IP (si se omite, entra en modo interactivo)")
    p.add_argument("-i", "--interactivo", action="store_true",
                   help="menu interactivo: eliges cada paso")
    p.add_argument("--pasiva", action="store_true", help="solo fase pasiva")
    p.add_argument("--activa", action="store_true", help="solo fase activa")
    p.add_argument("--puertos", default="comunes",
                   help="'comunes' (por defecto), 'all' (1-65535) o rango '1-1024'")
    p.add_argument("--timeout", type=float, default=1.0, help="timeout por puerto (s)")
    p.add_argument("--html", metavar="ARCHIVO", help="exporta el informe a HTML")
    p.add_argument("--no-color", action="store_true", help="desactiva los colores")
    args = p.parse_args()

    global USAR_COLOR
    _habilitar_terminal()
    if args.no_color:
        USAR_COLOR = False

    banner()

    # Modo interactivo: sin objetivo, o con -i
    if args.interactivo or not args.objetivo:
        modo_interactivo(args.objetivo, timeout=args.timeout)
        return

    # Seleccion de puertos (modo automatico clasico)
    if args.puertos == "comunes":
        puertos = sorted(PUERTOS_COMUNES)
    elif args.puertos == "all":
        puertos = range(1, 65536)
    elif "-" in args.puertos:
        a, b = args.puertos.split("-"); puertos = range(int(a), int(b) + 1)
    else:
        puertos = [int(x) for x in args.puertos.split(",")]

    objetivo = args.objetivo.strip().replace("https://", "").replace("http://", "").strip("/")
    print(c(f"  Objetivo: {objetivo}", C.BOLD + C.YELLOW))
    print(c(f"  Fecha:    {datetime.now():%d/%m/%Y %H:%M:%S}", C.DIM))

    es_dominio, ip = resolver_objetivo(objetivo)
    secciones_html = []

    hacer_pasiva = args.pasiva or not args.activa
    hacer_activa = args.activa or not args.pasiva

    if hacer_pasiva:
        fase_pasiva(objetivo, es_dominio, secciones_html)
    if hacer_activa:
        fase_activa(objetivo, ip, es_dominio, list(puertos), args.timeout, secciones_html)

    if args.html:
        ruta = generar_html(objetivo, secciones_html, args.html)
        titulo("INFORME")
        ok(f"Informe HTML guardado en: {c(os.path.abspath(ruta), C.CYAN)}")

    print(c("\n  Enumeracion finalizada.\n", C.GREEN + C.BOLD))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n  Interrumpido por el usuario.\n", C.YELLOW))
