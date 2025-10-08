# superscanner
Un scanner automatizado de redes
***POR MEJORAR***
A la espera de actualizaciones, pulidos y extensiones del código.

"""
Escáner híbrido:
 - Descubre hosts (ping / arp / input manual)
 - Escanea puertos TCP (connect), intenta banner grabbing
 - Hace probe UDP simple en puertos UDP comunes
 - Opcional: lanza nmap para verificación si está instalado
 - Modo interactivo: --prompt para pegar IPs manualmente (como un printf)
 - Guarda resultados en CSV/JSON

USO:
  python network_scanner_extensible.py              # intenta detectar /24 local y hace scans por defecto
  python network_scanner_extensible.py --subnet 192.168.1.0/24
  python network_scanner_extensible.py --ips 192.168.1.10,192.168.1.12
  python network_scanner_extensible.py --prompt     # te pedirá IPs por input()
  python network_scanner_extensible.py --no-udp     # no haga probe UDP
  python network_scanner_extensible.py --no-nmap    # no ejecute nmap
  python network_scanner_extensible.py --udp-ports 53,123,161 --tcp-ports 80,554
"""
