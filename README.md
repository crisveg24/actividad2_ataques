# Reconocimiento de Claro Colombia — Actividad No. 2: Detección de Intrusos

> **Materia:** Detección de Intrusos y Técnicas de Ataque  
> **Docente:** José Eduardo Patiño Santafé  
> **Carrera:** Ingeniería de Sistemas  
> **Fecha:** 19 de febrero de 2026  

---

## Tabla de Contenidos

1. [Objetivo](#objetivo)
2. [Víctima Seleccionada](#víctima-seleccionada)
3. [Herramientas Utilizadas](#herramientas-utilizadas)
4. [Requisitos](#requisitos)
5. [Ejecución del Script](#ejecución-del-script)
6. [Resultados por Herramienta](#resultados-por-herramienta)
   - [Herramienta 1: Nslookup / Resolución DNS](#herramienta-1-nslookup--resolución-dns)
   - [Herramienta 2: Enumeración de Subdominios](#herramienta-2-enumeración-de-subdominios)
   - [Herramienta 3: Whois (LACNIC)](#herramienta-3-whois-lacnic)
   - [Herramienta 4: Fingerprinting HTTP](#herramienta-4-fingerprinting-http)
   - [Herramienta 5: Certificados SSL](#herramienta-5-certificados-ssl)
   - [Herramienta 6: Robots.txt](#herramienta-6-robotstxt)
   - [Herramienta 7: Escaneo de Puertos TCP](#herramienta-7-escaneo-de-puertos-tcp)
   - [Herramienta 8: Registros TXT / SPF / MX / NS](#herramienta-8-registros-txt--spf--mx--ns)
7. [Resumen General de Hallazgos](#resumen-general-de-hallazgos)
8. [Google Dorks Sugeridos](#google-dorks-sugeridos)
9. [Capturas de Pantalla](#capturas-de-pantalla)
10. [Estructura del Proyecto](#estructura-del-proyecto)
11. [Disclaimer](#disclaimer)

---

## Objetivo

Realizar la búsqueda de información de una víctima utilizando **8 herramientas de reconocimiento** con el propósito de obtener información sensible: usuarios, archivos, dominios, subdominios, DNS, IPs, puertos abiertos, sistemas operativos, tecnologías y servicios expuestos.

Este trabajo corresponde al **Punto 1** de la Actividad No. 2 — Detección de Intrusos.

---

## Víctima Seleccionada

| Campo | Detalle |
|---|---|
| **Empresa** | Claro Colombia |
| **Dominio principal** | `claro.com.co` |
| **Razón social** | Comcel S.A. / Telmex Colombia S.A. |
| **Grupo corporativo** | América Móvil, S.A.B. de C.V. (México) |
| **Sector** | Telecomunicaciones |

---

## Herramientas Utilizadas

| # | Herramienta | Propósito |
|---|---|---|
| 1 | **Nslookup (DNS)** | Resolución de dominio, registros MX, NS, TXT |
| 2 | **Enumeración de Subdominios** | Fuerza bruta DNS con `socket` (40 prefijos) |
| 3 | **Whois (LACNIC)** | Propietario de IPs, rangos de red, contactos |
| 4 | **Fingerprinting HTTP** | Headers de servidores y tecnologías web |
| 5 | **Certificados SSL** | Organizaciones, emisores, subdominios ocultos (SANs) |
| 6 | **Robots.txt** | Rutas ocultas y archivos expuestos |
| 7 | **Escaneo de Puertos TCP** | Puertos abiertos en los servidores principales |
| 8 | **Registros TXT/SPF/MX/NS** | Servicios de terceros, correo, verificaciones |

Todas las herramientas están implementadas en un **único script Python** (`recon_claro_colombia.py`) usando exclusivamente la biblioteca estándar (no requiere instalaciones externas).

---

## Librerías Utilizadas

El script usa únicamente módulos de la **biblioteca estándar de Python** (no se necesita instalar nada con `pip`):

| Librería | Descripción | ¿Para qué la usamos? |
|---|---|---|
| `socket` | Comunicación de red a bajo nivel (TCP/UDP). Permite crear conexiones directas a servidores, resolver nombres de dominio a IPs y enviar/recibir datos por la red. | **Resolución DNS** (convertir `claro.com.co` → IP), **enumeración de subdominios** (probar miles de nombres), **Whois** (conectar al puerto 43 de LACNIC), y **escaneo de puertos** (verificar si un puerto TCP está abierto). |
| `ssl` | Implementación de TLS/SSL para conexiones cifradas. Permite establecer conexiones HTTPS seguras y extraer la información del certificado digital de un servidor. | **Certificados SSL** (extraer CN, organización, emisor, fechas de validez y SANs de cada servidor) y **fingerprinting HTTP** (conectar a sitios HTTPS sin que falle por certificados autofirmados). |
| `urllib.request` | Cliente HTTP de alto nivel. Permite hacer peticiones GET/POST a servidores web y leer las respuestas (headers y cuerpo). | **Fingerprinting HTTP** (obtener headers como `Server`, `X-Powered-By`, cookies) y **robots.txt** (descargar y analizar el contenido del archivo). |
| `concurrent.futures` | Ejecución paralela con hilos (`ThreadPoolExecutor`). Permite lanzar múltiples tareas simultáneamente y recoger los resultados con timeout. | **Enumeración de subdominios** (probar 40 subdominios en paralelo con 5 hilos en vez de uno por uno) y **escaneo de puertos** (escanear 16 puertos simultáneamente con 8 hilos por cada IP). |
| `sys` | Acceso a funciones del sistema y del intérprete Python. | Control de la salida del programa (flush de stdout para que la salida se muestre en tiempo real). |

> **Nota:** Al usar solo la biblioteca estándar, el script es **portable** — funciona en cualquier máquina con Python 3.8+ sin configuración adicional. Esto equivale funcionalmente a usar herramientas como `nslookup`, `wget`, `whois` y `nmap` desde la terminal, pero integrado en un solo programa.

### Equivalencia con las Herramientas del Enunciado

El enunciado de la actividad pide usar herramientas como **Google Dorks**, **HTTrack/WinHTTrack/WebHTTrack**, **Wget** y **5 herramientas adicionales**. En lugar de instalar cada programa por separado, se implementó todo en un **único script Python** usando las librerías estándar que replican la misma funcionalidad:

| Herramienta del enunciado | Equivalente en nuestro script | ¿Qué hace? |
|---|---|---|
| **Wget** | `urllib.request` | Wget descarga páginas y archivos desde la web por HTTP/HTTPS. Nuestra librería `urllib.request` hace exactamente lo mismo: envía peticiones HTTP, recibe respuestas, descarga contenido (robots.txt, headers, etc.). Es el Wget nativo de Python. |
| **HTTrack / WinHTTrack** | `urllib.request` + `ssl` | HTTrack clona sitios web descargando su HTML, CSS, imágenes y enlaces. Nuestro script usa `urllib` para descargar contenido web y `ssl` para acceder a sitios HTTPS — la misma operación base que realiza HTTrack internamente. |
| **Nslookup** | `socket.gethostbyname()` | Nslookup resuelve dominios a IPs. La función `gethostbyname()` de `socket` hace la misma consulta DNS. |
| **Whois** | `socket` (puerto 43) | El comando `whois` consulta el puerto 43 de servidores como LACNIC. Nuestro script abre un socket TCP al mismo puerto y envía la misma consulta. |
| **Nmap (escaneo de puertos)** | `socket.connect_ex()` | Nmap hace TCP connect scan. Nuestro `connect_ex()` intenta conectar a cada puerto y reporta si está abierto — es un TCP connect scan básico, igual que `nmap -sT`. |
| **Google Dorks** | Sección de dorks sugeridos | Se documentan los dorks recomendados para ejecutar manualmente en Google (no es automatizable sin API). |

> **¿Por qué Python en vez de las herramientas individuales?**  
> Usar Python permite tener **todo en un solo archivo ejecutable**, reproducible y documentado, sin depender de instalar Wget, HTTrack, Nmap o Whois por separado en cada máquina. Las librerías estándar de Python (`socket`, `ssl`, `urllib`) implementan los mismos protocolos de red (TCP, HTTP, DNS, TLS) que usan esas herramientas por debajo.

---

## Requisitos

- **Python 3.8+** (probado con Python 3.12)
- **Sistema Operativo:** Windows 10/11
- **Conexión a Internet** (para consultas DNS, HTTP y escaneo de puertos)
- No se requieren paquetes externos (`pip install` no es necesario)

---

## Ejecución del Script

```bash
# Clonar o descargar el repositorio
cd cyberseguridad

# Ejecutar el script completo
python recon_claro_colombia.py
```

El script ejecuta las 8 herramientas de forma secuencial y muestra un resumen consolidado al final. Si alguna herramienta falla o demora, se puede saltar con `Ctrl+C` sin interrumpir las demás.

**Tiempo estimado de ejecución:** ~1-2 minutos.

<!-- CAPTURA: Ejecución completa del script en terminal -->

---

## Resultados por Herramienta

### Herramienta 1: Nslookup / Resolución DNS

Resuelve el dominio `claro.com.co` a sus direcciones IP.

**Hallazgos:**

| Dominio | IPs Resueltas |
|---|---|
| `claro.com.co` | `201.161.119.36`, `201.161.119.37` |

Las IPs pertenecen a **Triara.com** (filial de Telmex en México), confirmando que la infraestructura principal está alojada fuera de Colombia.

<!-- CAPTURA: Salida de Herramienta 1 - Nslookup -->

---

### Herramienta 2: Enumeración de Subdominios

Realiza fuerza bruta DNS probando **40 prefijos** comunes contra `claro.com.co` usando hilos concurrentes (`ThreadPoolExecutor`).

**Subdominios encontrados (11):**

| Subdominio | IP | Observación |
|---|---|---|
| `www.claro.com.co` | `2.21.133.213` | Akamai CDN |
| `webmail.claro.com.co` | `200.14.253.220` | Correo web |
| `portal.claro.com.co` | `50.17.111.81` | AWS (Amazon) |
| `tienda.claro.com.co` | `186.80.47.254` | Telmex Colombia |
| `portalpagos.claro.com.co` | `2.21.133.194` | Akamai CDN |
| `oficinavirtualpqr.claro.com.co` | `20.85.43.30` | Azure (Microsoft) |
| `www2.claro.com.co` | `2.21.133.217` | Akamai CDN |
| `cdn.claro.com.co` | `186.80.47.254` | Telmex Colombia |
| `app.claro.com.co` | `166.210.224.181` | AT&T / Claro App |
| `miclaro.claro.com.co` | `201.161.119.37` | Triara México |
| `chat.claro.com.co` | `190.144.174.38` | Telmex Colombia |

<!-- CAPTURA: Salida de Herramienta 2 - Subdominios -->

---

### Herramienta 3: Whois (LACNIC)

Consulta directa al servidor `whois.lacnic.net` (puerto 43) para obtener información del propietario de las IPs.

**Hallazgos Whois:**

| IP Consultada | Propietario | País | Contacto |
|---|---|---|---|
| `201.161.119.36` | Triara.com S.A. de C.V. | México | jose.aguirre@triara.com |
| `186.80.47.254` | Telmex Colombia S.A. | Colombia | Tel: +57 01 7480000 |

- El rango `186.80.0.0/13` pertenece a Telmex Colombia.
- El rango `201.161.0.0/16` pertenece a Triara (datacenter de Telmex México).

<!-- CAPTURA: Salida de Herramienta 3 - Whois -->

---

### Herramienta 4: Fingerprinting HTTP

Analiza los headers HTTP de respuesta para identificar servidores y tecnologías.

**Tecnologías detectadas:**

| Subdominio | Servidor | Tecnología | Protocolo |
|---|---|---|---|
| `www.claro.com.co` | Nginx | Next.js | HTTPS |
| `tienda.claro.com.co` | Nginx | — | HTTPS |
| `portalpagos.claro.com.co` | Nginx | — | HTTPS |
| `oficinavirtualpqr.claro.com.co` | IIS 10.0 | ASP.NET Core | HTTPS |
| `portal.claro.com.co` | Apache | — | HTTPS |
| `www2.claro.com.co` | Nginx | — | HTTPS |
| `miclaro.claro.com.co` | Nginx 1.22.1 | — | HTTPS |

**Observaciones:**
- La versión expuesta de Nginx `1.22.1` en `miclaro` puede ser evaluada por vulnerabilidades conocidas.
- `oficinavirtualpqr` usa **IIS 10.0 + ASP.NET Core**, indicando infraestructura Windows Server en Azure.
- `www` usa **Next.js** (framework React), confirmando stack moderno.

<!-- CAPTURA: Salida de Herramienta 4 - HTTP Headers -->

---

### Herramienta 5: Certificados SSL

Extrae información de los certificados TLS/SSL de los servidores.

**Certificados analizados:**

| Subdominio | CN (Common Name) | Organización | Emisor | SANs |
|---|---|---|---|---|
| `www.claro.com.co` | `*.claro.com.co` | América Móvil | DigiCert | 2 (wildcard) |
| `tienda.claro.com.co` | `tienda.claro.com.co` | Comcel S.A. | GoDaddy | 7+ subdominios |
| `portalpagos.claro.com.co` | `*.claro.com.co` | América Móvil | DigiCert | 2 (wildcard) |
| `miclaro.claro.com.co` | `*.claro.com.co` | América Móvil | DigiCert | 2 (wildcard) |
| `oficinavirtualpqr.claro.com.co` | `*.claro.com.co` | — | Let's Encrypt | 1 |

**Subdominios descubiertos vía SANs del certificado de `tienda.claro.com.co`:**
- `seller.tienda.claro.com.co`
- `imagenes.seller.tienda.claro.com.co`
- `portalmayoristas.claro.com.co`
- `portalpagosapp.claro.com.co`
- `portalpagosecommerce.claro.com.co`
- `portalpagosempresa.claro.com.co`
- `portalpagosselfcare.claro.com.co`

<!-- CAPTURA: Salida de Herramienta 5 - Certificados SSL -->

---

### Herramienta 6: Robots.txt

Analiza el archivo `robots.txt` para encontrar rutas ocultas o restringidas.

**Resultados:**

| Sitio | Total Disallow | Rutas destacadas |
|---|---|---|
| `www.claro.com.co` | **252** | `/portal/recursos/`, `/services/*`, APIs internas, PDFs |
| `tienda.claro.com.co` | **27** | `/customer/`, `/checkout/`, `/catalogsearch/` |

**Rutas sensibles encontradas en `www`:**
- `/portal/recursos/` — Recursos internos, posibles documentos
- `/services/*` — Servicios backend / APIs
- Múltiples rutas a PDFs de planes y promociones
- Sitemaps XML referenciados

<!-- CAPTURA: Salida de Herramienta 6 - Robots.txt -->

---

### Herramienta 7: Escaneo de Puertos TCP

Escaneo de **16 puertos comunes** (FTP, SSH, HTTP, HTTPS, MySQL, RDP, etc.) contra 4 IPs principales.

**Puertos abiertos:**

| IP | Host | Puerto 80 (HTTP) | Puerto 443 (HTTPS) | Otros |
|---|---|---|---|---|
| `2.21.133.213` | www | ✅ Abierto | ✅ Abierto | — |
| `186.80.47.254` | tienda | ✅ Abierto | ✅ Abierto | — |
| `201.161.119.37` | miclaro | ✅ Abierto | ✅ Abierto | — |
| `20.85.43.30` | oficinavirtualpqr | ✅ Abierto | ✅ Abierto | — |

Puertos como SSH (22), FTP (21), MySQL (3306) y RDP (3389) se encuentran **filtrados/cerrados** en todas las IPs públicas, lo que indica buenas prácticas de firewall.

<!-- CAPTURA: Salida de Herramienta 7 - Escaneo de Puertos -->

---

### Herramienta 8: Registros TXT / SPF / MX / NS

Análisis de registros DNS avanzados obtenidos mediante `nslookup`.

#### Registros MX (Correo)
```
claro.com.co → claro-com-co.mail.protection.outlook.com
```
> Usan **Microsoft 365 / Outlook** para correo corporativo.

#### Registros NS (Servidores de nombres)
```
w2kbogccdnsec.comcel.com.co
w2kbogccdnses.comcel.com.co
w2kbogccdnsep.comcel.com.co
w2kbogccdnset.comcel.com.co
```
> DNS heredados de COMCEL. El prefijo `w2k` sugiere **Windows 2000**, `bog` = Bogotá.

#### Registros TXT / SPF
**Servicios de correo autorizados (SPF):**
| Servicio | Propósito |
|---|---|
| `spf.protection.outlook.com` | Microsoft 365 |
| `spf.mailjet.com` | Mailjet (email marketing) |
| `amazonses.com` | Amazon SES (envío masivo) |
| `_spf.salesforce.com` | Salesforce CRM |
| `claroco.embluejet.com` | emBlue (marketing local) |
| `spf.rpost.net` | Rpost (correo certificado) |
| `paradocmail.co` | Paradoc (correo certificado Colombia) |

**Verificaciones de servicios de terceros:**
| Token | Servicio |
|---|---|
| `google-site-verification` (×3) | Google Search Console |
| `MS=ms44608613` | Microsoft 365 |
| `atlassian-domain-verification` | Jira / Confluence |
| `Dynatrace-site-verification` | Monitoreo de rendimiento |
| `pexip-ms-tenant-domain-verification` | Pexip videoconferencias |
| `tmes=79a6f26e...` | Trend Micro Email Security |

<!-- CAPTURA: Salida de Herramienta 8 - Registros TXT -->

---

## Resumen General de Hallazgos

| Categoría | Hallazgo |
|---|---|
| **IPs principales** | `201.161.119.36/37` (Triara México) |
| **Subdominios** | 11 por DNS + 7 adicionales por SANs SSL |
| **Infraestructura** | Akamai CDN, AWS, Azure, Telmex/Triara |
| **Tecnologías** | Nginx, Next.js, Apache, IIS 10.0, ASP.NET Core |
| **Certificados** | DigiCert (wildcard), GoDaddy, Let's Encrypt |
| **DNS** | Comcel legacy (`w2kbogccd*.comcel.com.co`) |
| **Correo** | Microsoft 365 + Amazon SES, Mailjet, Salesforce |
| **Servicios terceros** | Google, Atlassian, Dynatrace, Pexip, Trend Micro |
| **Puertos** | 80 y 443 abiertos; resto filtrado |
| **Robots.txt** | 252 rutas ocultas en www, 27 en tienda |
| **Whois** | Triara México + Telmex Colombia |

---

## Google Dorks Sugeridos

Para complementar el reconocimiento, se pueden usar los siguientes dorks en Google:

```
site:claro.com.co filetype:pdf
site:claro.com.co intitle:"index of"
site:claro.com.co inurl:admin
site:claro.com.co inurl:login
inurl:claro.com.co ext:sql OR ext:bak OR ext:log
site:claro.com.co filetype:xlsx OR filetype:csv
site:claro.com.co "confidencial" OR "uso interno"
```

---

## Capturas de Pantalla

> **Instrucciones:** Reemplaza los comentarios `<!-- CAPTURA -->` por las imágenes correspondientes usando la sintaxis:
>
> ```markdown
> ![Descripción](ruta/a/la/imagen.png)
> ```

| # | Captura | Ubicación sugerida |
|---|---|---|
| 1 | Ejecución completa del script | Sección [Ejecución del Script](#ejecución-del-script) |
| 2 | Resultado Nslookup | Sección [Herramienta 1](#herramienta-1-nslookup--resolución-dns) |
| 3 | Subdominios encontrados | Sección [Herramienta 2](#herramienta-2-enumeración-de-subdominios) |
| 4 | Resultado Whois | Sección [Herramienta 3](#herramienta-3-whois-lacnic) |
| 5 | HTTP Headers | Sección [Herramienta 4](#herramienta-4-fingerprinting-http) |
| 6 | Certificados SSL | Sección [Herramienta 5](#herramienta-5-certificados-ssl) |
| 7 | Robots.txt | Sección [Herramienta 6](#herramienta-6-robotstxt) |
| 8 | Escaneo de puertos | Sección [Herramienta 7](#herramienta-7-escaneo-de-puertos-tcp) |
| 9 | Registros TXT/SPF | Sección [Herramienta 8](#herramienta-8-registros-txt--spf--mx--ns) |
| 10 | Resumen final | Sección [Resumen General](#resumen-general-de-hallazgos) |

---

## Estructura del Proyecto

```
cyberseguridad/
├── README.md                                           ← Este archivo
├── recon_claro_colombia.py                             ← Script principal de reconocimiento
├── Actividad No.2 Deteccion de intrusos.docx           ← Documento del grupo
└── Presentación_2_Detección de Intrusos y..._.pdf      ← Presentación del docente
```

---

## Disclaimer

Este proyecto fue realizado con fines **exclusivamente académicos** como parte de la asignatura de Detección de Intrusos. Todas las técnicas utilizadas son de **reconocimiento pasivo/semi-pasivo** y no implican explotación de vulnerabilidades ni acceso no autorizado a sistemas. La información recopilada es de carácter público.
