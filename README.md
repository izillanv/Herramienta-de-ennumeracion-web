# Herramienta-de-ennumeracion-web
<!-- Portada del repositorio -->
<h1 align="center">Reconocimiento y Cabeceras HTTP</h1>

<p align="center">
  Tres herramientas de ciberseguridad escritas en <b>Python 3</b> — reconocimiento
  (OSINT) pasivo y activo, análisis de cabeceras de seguridad, y un servidor que
  captura y analiza el <code>User-Agent</code> de cada visita.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/dependencias-0-2ea44f" alt="Sin dependencias">
  <img src="https://img.shields.io/badge/solo-stdlib-blue" alt="Solo librería estándar">
  <img src="https://img.shields.io/badge/SO-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Multiplataforma">
  <img src="https://img.shields.io/badge/licencia-educativa-orange" alt="Uso educativo">
</p>

---

Proyecto del módulo de **Ciberseguridad**. Tres scripts independientes, todos en
**Python 3 usando solo la librería estándar** (no requieren `pip install`), que
cubren el enunciado del ejercicio:

| # | Herramienta | Qué hace |
|---|-------------|----------|
| 1 | [`enumeracion.py`](#1-enumeracionpy--enumeración-pasiva-y-activa) | Enumeración **pasiva** y **activa** de un objetivo (con menú interactivo) |
| 2 | [`cabeceras_seguridad.py`](#2-cabeceras_seguridadpy--análisis-de-cabeceras-de-seguridad) | Analiza las **cabeceras de seguridad** de una web y le da una nota A–F |
| 3 | [`servidor_ua.py`](#3-servidor_uapy--servidor-que-captura-el-user-agent) | Servidor HTTP que **captura y analiza el User-Agent** de las peticiones |

> [!WARNING]
> **Uso responsable.** Ejecuta estas herramientas únicamente contra sistemas
> propios o con autorización expresa por escrito. El reconocimiento, el escaneo
> de puertos y el análisis no autorizados pueden ser ilegales.

---

## Requisitos

- **Python 3.7 o superior** (probado en 3.13).
- Sin dependencias externas. Nada que instalar.
- Funciona en Windows, Linux y macOS. Los colores de consola se activan solos
  (o se desactivan con `--no-color`).

## Instalación

```bash
git clone https://github.com/tu-usuario/reconocimiento-http.git
cd reconocimiento-http
```

Y listo — ya puedes ejecutar cualquiera de los tres scripts con `python`.

---

## 1) `enumeracion.py` — Enumeración pasiva y activa

Reúne las técnicas de reconocimiento vistas en clase.

**Fase PASIVA** (información pública, sin enviar tráfico al objetivo):
- **DNS** (A, AAAA, NS, MX, TXT, SOA, CNAME) mediante consulta UDP construida a mano.
- **WHOIS** — registrador, fechas, nameservers (protocolo WHOIS sobre TCP/43).
- **crt.sh** — subdominios a partir de los certificados TLS (*Certificate Transparency*).
- **robots.txt** — rutas que el objetivo pide no indexar.

**Fase ACTIVA** (se envían paquetes directamente al objetivo):
- **Escaneo de puertos TCP** (*connect scan*) multihilo + **captura de banners**.
- **Fingerprint HTTP** — cabecera `Server`, `X-Powered-By`, `<title>`.
- **Fuerza bruta de subdominios** por resolución DNS.

### Modo interactivo (recomendado)

Ejecutándolo **sin objetivo** (o con `-i`) entra en un menú donde **tú decides
cada paso** — no hace nada en la fase activa sin que lo elijas y lo confirmes:

```bash
python enumeracion.py                 # menú interactivo
python enumeracion.py example.com -i  # interactivo con el objetivo ya puesto
```

```
[1] Reconocimiento PASIVO completo     · todo lo pasivo + informe
[2] Reconocimiento ACTIVO completo     · todo lo activo + informe
[3] Enumeracion PASIVA (elegir modulos)
[4] Enumeracion ACTIVA (elegir puertos)
[5] Escanear un SUBDOMINIO descubierto
[6] Generar INFORME HTML
[7] Cambiar de objetivo
[0] Salir
```

Las opciones **1** y **2** hacen toda la fase y generan el informe solo
(`informe_pasivo_<obj>.html` / `informe_activo_<obj>.html`). La **5** lista los
subdominios hallados por crt.sh para que elijas cuáles escanear.

### Modo directo (línea de comandos)

```bash
python enumeracion.py example.com                  # pasiva + activa
python enumeracion.py example.com --pasiva          # solo pasiva
python enumeracion.py 192.168.1.1 --activa          # solo activa (IP)
python enumeracion.py example.com --puertos all     # todos los puertos (1-65535)
python enumeracion.py example.com --puertos 1-1024  # rango de puertos
python enumeracion.py example.com --html informe.html
```

**Salida:** consola con colores y, opcionalmente, un informe **HTML** con todas
las tablas (DNS, WHOIS, subdominios, puertos, fingerprint).

---

## 2) `cabeceras_seguridad.py` — Análisis de cabeceras de seguridad

Hace una petición HTTP(S) a la URL indicada y evalúa sus **cabeceras de
seguridad**, dando una **nota de A a F**.

Comprueba `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP),
`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy` y las `Cross-Origin-*`. Además detecta **fugas de
información** (`Server`, `X-Powered-By`…) y la **seguridad de las cookies**
(`Secure`, `HttpOnly`, `SameSite`).

```bash
python cabeceras_seguridad.py https://ejemplo.com          # genera informe automatico
python cabeceras_seguridad.py ejemplo.com otra.com         # varias URLs de golpe
python cabeceras_seguridad.py ejemplo.com --html informe.html   # nombre a medida
```

**Salida:** por cada cabecera `[ OK ] / [WARN] / [FAIL]`, puntuación con barra de
progreso, y **siempre un informe HTML**. Sin `--html` se guarda como
`informe_cabeceras_<web>.html`.

---

## 3) `servidor_ua.py` — Servidor que captura el User-Agent

Levanta un servidor HTTP. De **cada petición** captura la cabecera `User-Agent`
(más IP, método, ruta, hora), la **parsea** (navegador + versión, sistema
operativo, tipo de dispositivo, y si es un bot) y la guarda en memoria y en disco
(`capturas_ua.json`).

**Cómo enseña la información:**
- **Log en consola**, una línea por petición.
- **Panel web en vivo** en `http://localhost:PUERTO/`: contadores, gráficos de
  barras por navegador / SO / dispositivo y tabla de las últimas peticiones.
  Se refresca solo cada 2 segundos.
- **API JSON** en `/api/data`.

```bash
python servidor_ua.py                  # escucha en 127.0.0.1:8080
python servidor_ua.py --puerto 9000
python servidor_ua.py --host 0.0.0.0   # accesible desde la red local
```

Abre `http://localhost:8080/` y, para generar tráfico de prueba, en **otra**
terminal:

```bash
curl http://localhost:8080/hola
curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" http://localhost:8080/contacto
curl -A "Googlebot/2.1 (+http://www.google.com/bot.html)" http://localhost:8080/robots.txt
```

> [!NOTE]
> Abrir `http://localhost:8080/` es el **panel** y *no* cuenta como visita. Las
> visitas capturadas son las demás rutas. El `-A "..."` falsea el User-Agent,
> para ver cómo clasifica cada tipo.

---

## Investigación: ¿qué se puede hacer con el User-Agent?

El **User-Agent (UA)** es una cabecera que el cliente (navegador, app, bot…) envía
en cada petición HTTP, identificando el software que la hace. De ella se deduce
navegador, versión, motor, sistema operativo y arquitectura.

<details>
<summary><b>Ver investigación completa</b></summary>

### Usos legítimos
- **Analítica web** — saber qué navegadores/SO/dispositivos usan los visitantes.
- **Detección de dispositivo** — servir versión móvil o de escritorio.
- **Compatibilidad** — *polyfills* o rutas de código según el navegador.
- **Depuración y soporte** — reproducir fallos de una combinación concreta.

### Usos de seguridad (defensivos)
- **Detección y bloqueo de bots/scrapers** — muchos se identifican en el UA
  (`curl`, `python-requests`, `sqlmap`, `nmap`, `Googlebot`…). Permite filtrar
  tráfico automatizado o aplicar *rate limiting*. **Es lo que hace `servidor_ua.py`.**
- **Reglas de WAF** — bloquear UA de herramientas ofensivas conocidas.
- **Detección de anomalías** — un UA vacío, malformado o incoherente con el resto
  de cabeceras es señal de automatización o suplantación.

### Usos ofensivos / abusos
- **Fingerprinting y perfilado** — combinado con otras señales ayuda a rastrear a
  un usuario aunque borre las cookies (problema de **privacidad**).
- **Selección de objetivos** — servir un *exploit* distinto según navegador/SO.
- **User-Agent spoofing** — el UA lo controla el cliente, así que se falsea
  trivialmente (`curl -A "..."`). Por eso **nunca debe usarse como control de
  seguridad** por sí solo.
- **Inyección a través del UA** — como suele guardarse/mostrarse en paneles y
  logs, si no se sanea puede provocar **XSS almacenado**, **SQL injection** o
  *log poisoning*. *(En `servidor_ua.py` el UA se escapa con `html.escape`
  precisamente para evitar el XSS en el panel.)*

### Hacia dónde va: Client Hints
Por los problemas de privacidad, los navegadores están **recortando** el UA
(*UA reduction*) y lo sustituyen por **User-Agent Client Hints** (`Sec-CH-UA`,
`Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile`…), que el servidor pide explícitamente.

### Conclusión
El User-Agent sirve para **analítica, adaptación de contenido y detección de
bots**, pero al ser un dato **que controla el cliente y fácil de falsear**, en
seguridad vale para *detectar y filtrar*, nunca para *confiar*. Como todo dato de
entrada, **hay que tratarlo como no confiable y sanearlo** antes de registrarlo o
mostrarlo.

</details>

---

## Cómo se relacionan las tres herramientas

El hilo que las une son **las cabeceras HTTP y la información que filtran**, vistas
desde los dos lados de la conexión:

```
  CLIENTE  ──── petición (lleva User-Agent) ────►  SERVIDOR
  CLIENTE  ◄─── respuesta (lleva Server, HSTS) ───  SERVIDOR
```

- **`cabeceras_seguridad.py`** → eres el **cliente**: analizas las cabeceras de
  **respuesta** del servidor (qué revela y cómo de protegido está).
- **`servidor_ua.py`** → eres el **servidor**: analizas las cabeceras de
  **petición** del cliente (qué revela de sí mismo, su User-Agent).
- **`enumeracion.py`** → el marco general de reconocimiento donde todo encaja.

---

## Estructura del proyecto

```
.
├── enumeracion.py              # Enumeración pasiva + activa (con modo interactivo)
├── cabeceras_seguridad.py      # Análisis de cabeceras de seguridad HTTP
├── servidor_ua.py              # Servidor de captura de User-Agent + panel web
└── README.md                   # Este archivo

# Archivos generados al usar las herramientas (no se versionan):
#   informe_pasivo_<obj>.html       Informe del reconocimiento pasivo
#   informe_activo_<obj>.html       Informe del reconocimiento activo
#   informe_cabeceras_<web>.html    Informe del análisis de cabeceras
#   capturas_ua.json                Capturas del servidor de User-Agent
```

---

## Autor

**Izan Villalba** — Ejercicio de Ciberseguridad.

## Licencia

Proyecto con fines **educativos**. Úsalo y modifícalo libremente para aprender.
