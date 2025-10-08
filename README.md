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

  python superscanner.py                                         # intenta detectar /24 local y hace scans por defecto
  
  python superscanner.py --subnet 192.168.1.0/24
  
  python superscanner.py --ips 192.168.1.10,192.168.1.12
  
  python superscanner.py --prompt                                  # te pedirá IPs por input()
  
  python superscanner.py --no-udp                                  # no hace probe UDP
  
  python superscanner.py --no-nmap                                 # no ejecuta nmap
  
  python superscanner.py --udp-ports 53,123,161 --tcp-ports 80,554
  
"""
