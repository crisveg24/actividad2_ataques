"""
=============================================================================
RECONOCIMIENTO DE CLARO COLOMBIA (claro.com.co)
Actividad No. 2 - Deteccion de Intrusos - Punto 1
=============================================================================
Victima: Claro Colombia / Telmex Colombia
Dominio: claro.com.co

Herramientas utilizadas:
  1. Nslookup (DNS)        - Resolucion de dominio, registros MX, NS, TXT
  2. Enumeracion de subdominios - Fuerza bruta DNS con socket
  3. Whois (LACNIC)        - Propietario de IPs y dominios
  4. Fingerprinting HTTP   - Headers de servidores y tecnologias
  5. Certificados SSL      - Organizaciones, emisores, subdominios ocultos
  6. Robots.txt            - Rutas ocultas y archivos expuestos
  7. Escaneo de puertos    - Puertos TCP abiertos
  8. Registros TXT/SPF     - Servicios de terceros, correo, verificaciones

Fecha de ejecucion: 19 de febrero de 2026
=============================================================================
"""

import socket
import ssl
import urllib.request
import concurrent.futures
import sys

# ============================================================
# CONFIGURACION
# ============================================================
DOMINIO = "claro.com.co"
DNS_TIMEOUT = 2
HTTP_TIMEOUT = 5
PORT_TIMEOUT = 1
WHOIS_TIMEOUT = 8

# Subdominios que sabemos responden por HTTP (no cuelgan)
SUBDOMINIOS_HTTP = [
    ('www.claro.com.co', '2.21.133.213'),
    ('tienda.claro.com.co', '186.80.47.254'),
    ('portalpagos.claro.com.co', '2.21.133.194'),
    ('oficinavirtualpqr.claro.com.co', '20.85.43.30'),
    ('portal.claro.com.co', '50.17.111.81'),
    ('www2.claro.com.co', '2.21.133.217'),
    ('miclaro.claro.com.co', '201.161.119.37'),
]

# Subdominios con SSL accesible
SUBDOMINIOS_SSL = [
    'www.claro.com.co',
    'tienda.claro.com.co',
    'portalpagos.claro.com.co',
    'miclaro.claro.com.co',
    'oficinavirtualpqr.claro.com.co',
]

# IPs principales para escaneo de puertos
IPS_PUERTOS = [
    ('www.claro.com.co', '2.21.133.213'),
    ('tienda.claro.com.co', '186.80.47.254'),
    ('miclaro.claro.com.co', '201.161.119.37'),
    ('oficinavirtualpqr.claro.com.co', '20.85.43.30'),
]

# Respaldo si la enumeracion falla
SUBDOMINIOS_RESPALDO = [
    ('www.claro.com.co', '2.21.133.213'),
    ('webmail.claro.com.co', '200.14.253.220'),
    ('portal.claro.com.co', '50.17.111.81'),
    ('tienda.claro.com.co', '186.80.47.254'),
    ('portalpagos.claro.com.co', '2.21.133.194'),
    ('oficinavirtualpqr.claro.com.co', '20.85.43.30'),
    ('www2.claro.com.co', '2.21.133.217'),
    ('cdn.claro.com.co', '186.80.47.254'),
    ('app.claro.com.co', '166.210.224.181'),
    ('miclaro.claro.com.co', '201.161.119.37'),
    ('chat.claro.com.co', '190.144.174.38'),
]


def separador(titulo):
    print(f"\n{'='*70}")
    print(f"  {titulo}")
    print(f"{'='*70}\n")


# ============================================================
# HERRAMIENTA 1: NSLOOKUP / RESOLUCION DNS
# ============================================================

def herramienta_1_nslookup():
    separador("HERRAMIENTA 1: NSLOOKUP - RESOLUCION DNS")
    print("Comando equivalente: nslookup claro.com.co")
    print("-" * 50)
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        ips = socket.gethostbyname_ex(DOMINIO)
        socket.setdefaulttimeout(old)
        print(f"Dominio: {ips[0]}")
        print(f"Aliases: {ips[1]}")
        print(f"IPs:     {ips[2]}")
    except Exception as e:
        print(f"Error: {e}")
    print()


# ============================================================
# HERRAMIENTA 2: ENUMERACION DE SUBDOMINIOS
# ============================================================

def _resolver_uno(sub):
    """Intenta resolver un subdominio. Retorna tupla o None."""
    dominio = f"{sub}.{DOMINIO}"
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(DNS_TIMEOUT)
        ip = socket.gethostbyname(dominio)
        socket.setdefaulttimeout(old)
        return (dominio, ip)
    except Exception:
        return None


def herramienta_2_enumeracion_subdominios():
    separador("HERRAMIENTA 2: ENUMERACION DE SUBDOMINIOS")

    lista = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop',
        'ns1', 'ns2', 'vpn', 'admin', 'portal', 'tienda',
        'portalpagos', 'oficinavirtualpqr', 'www2', 'api',
        'cdn', 'dev', 'test', 'staging', 'intranet', 'correo',
        'mx', 'dns', 'app', 'movil', 'secure', 'login',
        'extranet', 'soporte', 'ayuda', 'factura', 'micuenta',
        'miclaro', 'pqr', 'chat', 'blog', 'pagos', 'store', 'shop'
    ]

    print(f"Probando {len(lista)} subdominios contra {DOMINIO}...")
    print(f"(Timeout: {DNS_TIMEOUT}s por consulta, max 60s total)")
    print("-" * 50)

    encontrados = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            futuros = {pool.submit(_resolver_uno, s): s for s in lista}
            for f in concurrent.futures.as_completed(futuros, timeout=60):
                try:
                    r = f.result(timeout=DNS_TIMEOUT + 1)
                    if r:
                        print(f"  [+] {r[0]:45s} -> {r[1]}")
                        encontrados.append(r)
                except Exception:
                    pass
    except concurrent.futures.TimeoutError:
        print("  [!] Timeout global, continuando con lo encontrado...")
    except Exception as e:
        print(f"  [!] Error: {e}")

    if not encontrados:
        print("  [*] Sin resultados DNS, usando datos de sesion anterior...")
        encontrados = SUBDOMINIOS_RESPALDO

    print(f"\nTotal subdominios: {len(encontrados)}")
    return encontrados


# ============================================================
# HERRAMIENTA 3: WHOIS (LACNIC)
# ============================================================

def herramienta_3_whois():
    separador("HERRAMIENTA 3: WHOIS (LACNIC)")

    ips = [
        ("dominio principal", "201.161.119.36"),
        ("tienda/cdn Telmex CO", "186.80.47.254"),
    ]

    for nombre, ip in ips:
        print(f"--- WHOIS {ip} ({nombre}) ---")
        try:
            server_ip = socket.gethostbyname('whois.lacnic.net')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(WHOIS_TIMEOUT)
            s.connect((server_ip, 43))
            s.send((ip + '\r\n').encode())
            response = b''
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
                except Exception:
                    break
            s.close()
            texto = response.decode('utf-8', errors='ignore')
            for linea in texto.split('\n'):
                linea = linea.strip()
                if linea and not linea.startswith('%'):
                    print(f"  {linea}")
        except Exception as e:
            print(f"  Error: {e}")
        print()


# ============================================================
# HERRAMIENTA 4: FINGERPRINTING HTTP
# ============================================================

def herramienta_4_fingerprinting_http():
    separador("HERRAMIENTA 4: FINGERPRINTING HTTP (Headers)")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers_interes = [
        'Server', 'X-Powered-By', 'X-Frame-Options',
        'Content-Type', 'Set-Cookie', 'X-AspNet-Version',
        'Strict-Transport-Security'
    ]

    for dominio, ip in SUBDOMINIOS_HTTP:
        print(f"--- {dominio} ({ip}) ---")
        ok = False
        for proto in ['https', 'http']:
            try:
                url = f'{proto}://{dominio}/'
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                resp = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx)
                print(f"  Protocolo: {proto.upper()} | Status: {resp.status}")
                for h in headers_interes:
                    val = resp.getheader(h)
                    if val:
                        print(f"  {h}: {val[:120]}")
                ok = True
                break
            except urllib.error.HTTPError as e:
                print(f"  {proto.upper()} -> HTTP {e.code}")
                for h in ['Server', 'X-Powered-By']:
                    val = e.headers.get(h)
                    if val:
                        print(f"  {h}: {val[:120]}")
                ok = True
                break
            except Exception:
                continue
        if not ok:
            print(f"  Sin respuesta (timeout {HTTP_TIMEOUT}s)")
        print()


# ============================================================
# HERRAMIENTA 5: CERTIFICADOS SSL
# ============================================================

def herramienta_5_certificados_ssl():
    separador("HERRAMIENTA 5: CERTIFICADOS SSL")

    ctx = ssl.create_default_context()

    for dominio in SUBDOMINIOS_SSL:
        print(f"--- Certificado: {dominio} ---")
        try:
            conn = ctx.wrap_socket(socket.socket(), server_hostname=dominio)
            conn.settimeout(HTTP_TIMEOUT)
            conn.connect((dominio, 443))
            cert = conn.getpeercert()

            subj = dict(x[0] for x in cert.get('subject', ()))
            issuer = dict(x[0] for x in cert.get('issuer', ()))

            print(f"  CN:           {subj.get('commonName', 'N/A')}")
            print(f"  Organizacion: {subj.get('organizationName', 'N/A')}")
            print(f"  Emisor:       {issuer.get('organizationName', 'N/A')} - {issuer.get('commonName', 'N/A')}")
            print(f"  Valido desde: {cert.get('notBefore', 'N/A')}")
            print(f"  Valido hasta: {cert.get('notAfter', 'N/A')}")

            sans = [v for t, v in cert.get('subjectAltName', ()) if t == 'DNS']
            if sans:
                print(f"  SANs ({len(sans)}): {', '.join(sans[:10])}")

            conn.close()
        except Exception as e:
            print(f"  Error: {str(e)[:100]}")
        print()


# ============================================================
# HERRAMIENTA 6: ROBOTS.TXT
# ============================================================

def herramienta_6_robots_txt():
    separador("HERRAMIENTA 6: ANALISIS DE ROBOTS.TXT")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    urls = [
        f'https://www.{DOMINIO}/robots.txt',
        f'https://tienda.{DOMINIO}/robots.txt',
    ]

    for url in urls:
        nombre = url.split('//')[1].split('/')[0]
        print(f"--- {nombre} ---")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx)
            text = resp.read().decode('utf-8', errors='ignore')
            lineas = text.strip().split('\n')
            disallows = [l.strip() for l in lineas if l.strip().startswith('Disallow')]
            sitemaps = [l.strip() for l in lineas if 'sitemap' in l.lower()]
            print(f"  Total Disallow: {len(disallows)}")
            print(f"  Rutas ocultas:")
            for d in disallows[:15]:
                print(f"    {d}")
            if len(disallows) > 15:
                print(f"    ... y {len(disallows)-15} mas")
            if sitemaps:
                for s in sitemaps:
                    print(f"  {s.strip()}")
        except urllib.error.HTTPError as e:
            print(f"  No disponible (HTTP {e.code})")
        except Exception as e:
            print(f"  Error: {str(e)[:80]}")
        print()


# ============================================================
# HERRAMIENTA 7: ESCANEO DE PUERTOS TCP
# ============================================================

def _scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PORT_TIMEOUT)
        r = s.connect_ex((ip, port))
        s.close()
        return port if r == 0 else None
    except Exception:
        return None


def herramienta_7_escaneo_puertos():
    separador("HERRAMIENTA 7: ESCANEO DE PUERTOS TCP")

    puertos = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 3306, 3389, 8080, 8443]
    nombres = {
        21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
        80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
        587:'SMTP-TLS', 993:'IMAPS', 3306:'MySQL', 3389:'RDP',
        8080:'HTTP-Alt', 8443:'HTTPS-Alt'
    }

    for dom, ip in IPS_PUERTOS:
        print(f"--- {ip} ({dom}) ---")
        abiertos = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            fs = {pool.submit(_scan_port, ip, p): p for p in puertos}
            try:
                for f in concurrent.futures.as_completed(fs, timeout=25):
                    r = f.result(timeout=2)
                    if r is not None:
                        abiertos.append(r)
                        print(f"  [ABIERTO] {r}/{nombres.get(r, '?')}")
            except concurrent.futures.TimeoutError:
                print("  [!] Timeout")
        if not abiertos:
            print("  Sin puertos comunes abiertos (filtrados)")
        else:
            print(f"  Total: {len(abiertos)}")
        print()


# ============================================================
# HERRAMIENTA 8: REGISTROS TXT / SPF / MX / NS
# ============================================================

def herramienta_8_registros_txt():
    separador("HERRAMIENTA 8: REGISTROS TXT / SPF / MX / NS")

    print("Comandos ejecutados previamente en consola:")
    print("  > nslookup -type=MX claro.com.co 8.8.8.8")
    print("  > nslookup -type=NS claro.com.co 8.8.8.8")
    print("  > nslookup -type=TXT claro.com.co 8.8.8.8")
    print()
    print("--- REGISTROS MX (Servidores de correo) ---")
    print("  claro.com.co MX -> claro-com-co.mail.protection.outlook.com")
    print("  >> Usa Microsoft 365 / Outlook para correo corporativo")
    print()
    print("--- REGISTROS NS (Servidores de nombres) ---")
    print("  w2kbogccdnsec.comcel.com.co")
    print("  w2kbogccdnses.comcel.com.co")
    print("  w2kbogccdnsep.comcel.com.co")
    print("  w2kbogccdnset.comcel.com.co")
    print("  >> DNS heredados de COMCEL, 'w2k' = Windows 2000, 'bog' = Bogota")
    print()
    print("--- REGISTROS TXT (Hallazgos clave) ---")
    print()
    print("  [SPF - Servidores autorizados para enviar correo]")
    print("  v=spf1 include:spf.protection.outlook.com")
    print("         include:spfs.claro.com.co")
    print("         include:paradocmail.co")
    print("         include:spf.mailjet.com")
    print("         include:claroco.embluejet.com")
    print("         include:amazonses.com")
    print("         include:spf.rpost.net")
    print("         include:_spf.salesforce.com -all")
    print("  >> Outlook, Mailjet, Amazon SES, Salesforce, emBlue, Rpost")
    print()
    print("  [DKIM - Firma de correo]")
    print("  v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNAD...")
    print()
    print("  [Verificaciones de servicios terceros]")
    print("  google-site-verification (3 tokens) -> Google Search Console")
    print("  MS=ms44608613                       -> Microsoft 365")
    print("  atlassian-domain-verification       -> Jira/Confluence")
    print("  Dynatrace-site-verification         -> Monitoreo rendimiento")
    print("  pexip-ms-tenant-domain-verification -> Pexip videoconferencias")
    print("  a:mail.sealmail.co                  -> SealMail correo certificado")
    print("  tmes=79a6f26e...                    -> Trend Micro Email Security")
    print()
    print("  + ~25 tokens alfanumericos de verificacion de propiedad")


# ============================================================
# RESUMEN
# ============================================================

def resumen_hallazgos():
    separador("RESUMEN DE TODA LA INFORMACION OBTENIDA")
    print("""
VICTIMA: Claro Colombia (claro.com.co) / Telmex Colombia / Comcel S.A.
GRUPO:   America Movil, S.A.B. de C.V. (Mexico)

1. IPs PRINCIPALES
   201.161.119.36/37 -> Triara.com (filial Telmex Mexico)

2. SUBDOMINIOS (11 + 7 via SSL)
   www, webmail, portal, tienda, portalpagos, oficinavirtualpqr,
   www2, cdn, app, miclaro, chat
   SSL: seller.tienda, imagenes.seller.tienda, portalmayoristas,
        portalpagosapp, portalpagosecommerce, portalpagosempresa,
        portalpagosselfcare

3. INFRAESTRUCTURA
   Akamai CDN (www, www2, portalpagos) | AWS (portal)
   Azure (oficinavirtualpqr) | Telmex/Triara (tienda, cdn, miclaro)

4. TECNOLOGIAS
   Nginx | Next.js | Apache | IIS 10.0 + ASP.NET Core | Nginx 1.22.1

5. CERTIFICADOS SSL
   DigiCert (wildcard) | GoDaddy | Let's Encrypt
   Orgs: America Movil S.A.B. DE C.V. | Comcel S.A.

6. DNS: Comcel legacy (w2kbogccd*.comcel.com.co)

7. CORREO: Microsoft 365 + Amazon SES, Mailjet, Salesforce, emBlue

8. SERVICIOS: Google, MS365, Atlassian, Dynatrace, Pexip, Trend Micro

9. PUERTOS: 80/HTTP y 443/HTTPS en servidores principales

10. ROBOTS.TXT: APIs internas, PDFs, /portal/recursos/, /services/*

11. WHOIS: Triara Mexico (201.161.x) | Telmex Colombia (186.80.x)
    Contacto: jose.aguirre@triara.com | Tel: +57 01 7480000

12. GOOGLE DORKS SUGERIDOS:
    site:claro.com.co filetype:pdf
    site:claro.com.co intitle:"index of"
    site:claro.com.co inurl:admin
    site:claro.com.co inurl:login
    inurl:claro.com.co ext:sql OR ext:bak OR ext:log
""")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  RECONOCIMIENTO DE CLARO COLOMBIA - claro.com.co")
    print("  Fecha: 19 de febrero de 2026")
    print("=" * 70)

    pasos = [
        ("1/8 DNS",           herramienta_1_nslookup),
        ("2/8 Subdominios",   herramienta_2_enumeracion_subdominios),
        ("3/8 Whois",         herramienta_3_whois),
        ("4/8 HTTP Headers",  herramienta_4_fingerprinting_http),
        ("5/8 SSL Certs",     herramienta_5_certificados_ssl),
        ("6/8 Robots.txt",    herramienta_6_robots_txt),
        ("7/8 Puertos",       herramienta_7_escaneo_puertos),
        ("8/8 TXT/SPF/MX",   herramienta_8_registros_txt),
    ]

    for nombre, func in pasos:
        print(f"\n>>> Ejecutando {nombre}...")
        try:
            func()
        except KeyboardInterrupt:
            print(f"\n  [!] Saltando {nombre} (Ctrl+C)")
            continue
        except Exception as e:
            print(f"  [!] Error en {nombre}: {e}")
            continue

    resumen_hallazgos()
    print("[FIN DEL RECONOCIMIENTO]")
