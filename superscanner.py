#!/usr/bin/env python3
"""
network_scanner_extensible.py

Escáner híbrido extensible:
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

import argparse
import ipaddress
import platform
import subprocess
import socket
import sys
import csv
import json
import time
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- Config ----------------
DEFAULT_TCP_PORTS = [21,22,23,25,53,80,81,88,110,111,123,135,137,138,139,143,161,179,389,443,445,554,631,636,8000,8080,8443,8554,9000,9090,37777,5000]
DEFAULT_UDP_PORTS = [53,67,68,69,123,161,500,4500]
SOCKET_TIMEOUT = 1.0
UDP_TIMEOUT = 1.0
PING_TIMEOUT = 1
DEFAULT_THREADS = 100
OUT_CSV = "scan_combined_ext.csv"
OUT_JSON = "scan_combined_ext.json"
# ----------------------------------------

def detect_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(local_ip + "/24", strict=False))
    except Exception:
        return None

def run_cmd_quiet(cmd, timeout=5):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return proc.returncode, proc.stdout.decode(errors="ignore"), proc.stderr.decode(errors="ignore")
    except Exception as e:
        return 1, "", str(e)

def ping_host(ip):
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT*1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip]
    rc, _, _ = run_cmd_quiet(cmd, timeout=PING_TIMEOUT+1)
    return rc == 0

def arp_table_hosts():
    """Parsea salida de 'arp -a' para recoger IPs y MACs locales."""
    system = platform.system()
    if system == "Windows":
        cmd = ["arp", "-a"]
    else:
        # linux/mac
        cmd = ["arp", "-a"]
    rc, out, err = run_cmd_quiet(cmd, timeout=3)
    entries = []
    if rc != 0 or not out:
        return entries
    for line in out.splitlines():
        line = line.strip()
        # ejemplos variados; intentamos extraer ip y mac si aparecen
        # Windows: ? (192.168.1.1) at aa-bb-cc-dd-ee-ff [ether] on ...
        # Unix: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        parts = line.split()
        ip = None
        mac = None
        for p in parts:
            if p.startswith("(") and p.endswith(")"):
                ip = p.strip("()")
            if (":" in p or "-" in p) and len(p) >= 7:
                mac = p.replace("-", ":")
        if ip:
            entries.append({"ip": ip, "mac": mac, "raw": line})
    return entries

def is_port_open_tcp(host, port, timeout=SOCKET_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return True
    except Exception:
        return False

def grab_banner_tcp(host, port, timeout=SOCKET_TIMEOUT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # probe HTTP-like for http ports
        if port in (80, 8080, 8000, 8443, 554):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass
        data = b""
        try:
            data = s.recv(2048)
        except Exception:
            pass
        s.close()
        if data:
            st = data.decode(errors="ignore").strip()
            st = " ".join(st.split())
            return st[:800]
        return ""
    except Exception:
        return ""

def udp_probe(host, port, timeout=UDP_TIMEOUT):
    """
    Intento simple de probe UDP:
     -Enviar un paquete vacío o pequeño y esperar recvfrom (algunas implementaciones responden).
     -No garantiza detección, pero puede descubrir servicios como DNS/NTP/MDNS.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        msg = b"\x00"  # small probe
        try:
            sock.sendto(msg, (host, port))
        except Exception:
            sock.close()
            return False, "send-failed"
        try:
            data, addr = sock.recvfrom(2048)
            sock.close()
            return True, ("recv", len(data))
        except socket.timeout:
            sock.close()
            return False, "no-reply"
        except Exception as e:
            sock.close()
            return False, f"err:{e}"
    except Exception as e:
        return False, f"err:{e}"

def run_nmap(hosts, port_spec, nmap_args="-sS -sV -Pn", out_xml="nmap_out.xml"):
    if not shutil.which("nmap"):
        return {}
    # construir comando
    # nota: si hosts many, pasamos como lista de hosts seguidos
    hosts_str = " ".join(hosts)
    cmd = f"nmap {nmap_args} -p {port_spec} -oX {out_xml} {hosts_str}"
    print("[*] Ejecutando nmap:", cmd)
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    except subprocess.TimeoutExpired:
        print("[!] nmap timeout")
        return {}
    # parseo básico XML si generado
    results = {}
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(out_xml)
        root = tree.getroot()
        for h in root.findall("host"):
            addr = None
            for a in h.findall("address"):
                if a.get("addrtype") == "ipv4":
                    addr = a.get("addr")
            if not addr:
                continue
            ports = []
            ports_elem = h.find("ports")
            if ports_elem is None:
                continue
            for p in ports_elem.findall("port"):
                pid = int(p.get("portid"))
                state = p.find("state").get("state") if p.find("state") is not None else "unknown"
                serv = p.find("service")
                svc = serv.get("name") if serv is not None and "name" in serv.attrib else ""
                ver = ""
                if serv is not None and "product" in serv.attrib:
                    ver = serv.get("product", "") + " " + serv.get("version", "")
                ports.append({"port": pid, "state": state, "service": svc, "version": ver})
            results[addr] = ports
    except Exception as e:
        print("[!] Error parsing nmap XML:", e)
    return results

def generate_ips_from_subnet(subnet):
    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses > 4096:
        raise ValueError("Rango muy grande; especifica subred más pequeña o lista de IPs.")
    return [str(ip) for ip in net.hosts()]

def prompt_for_ips():
    s = input("Introduce IPs separadas por comas (ej: 192.168.1.10,192.168.1.12) >>> ").strip()
    if not s:
        return []
    return [ip.strip() for ip in s.split(",") if ip.strip()]

def save_outputs(data, csvfile=OUT_CSV, jsonfile=OUT_JSON):
    # CSV rows flattened
    rows = []
    for host, info in data.items():
        row_base = {
            "host": host,
            "mac": info.get("mac",""),
            "alive": info.get("alive", False),
            "note": info.get("note","")
        }
        for p in info.get("tcp", []):
            r = row_base.copy()
            r.update({"proto":"tcp","port": p["port"], "open": p["open"], "banner": p.get("banner",""), "source": ",".join(p.get("source",[]))})
            rows.append(r)
        for u in info.get("udp", []):
            r = row_base.copy()
            r.update({"proto":"udp","port": u["port"], "open": u["open"], "banner": u.get("note",""), "source": ",".join(u.get("source",[]))})
            rows.append(r)
        if not info.get("tcp") and not info.get("udp"):
            r = row_base.copy()
            r.update({"proto":"","port":"","open":"","banner":"","source":""})
            rows.append(r)
    # CSV
    with open(csvfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host","mac","alive","proto","port","open","banner","source","note"])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    # JSON
    with open(jsonfile, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] Guardado CSV: {csvfile} y JSON: {jsonfile}")

def main():
    parser = argparse.ArgumentParser(description="Network scanner extensible (TCP/UDP/ARP/nmap + prompt).")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--subnet", help="CIDR a escanear (ej: 192.168.1.0/24). Si omites, intenta detectar /24 local.")
    group.add_argument("--ips", help="IPs separadas por coma")
    parser.add_argument("--prompt", action="store_true", help="Pide IPs manualmente por input() (modo interactivo).")
    parser.add_argument("--tcp-ports", help="Lista puertos TCP separados por coma (ej: 80,554).")
    parser.add_argument("--udp-ports", help="Lista puertos UDP separados por coma.")
    parser.add_argument("--no-udp", action="store_true", help="No lanzar probes UDP.")
    parser.add_argument("--no-nmap", action="store_true", help="No ejecutar nmap aunque esté instalado.")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--out-csv", default=OUT_CSV)
    parser.add_argument("--out-json", default=OUT_JSON)
    args = parser.parse_args()

    # construir lista de ips
    ips = []
    if args.prompt:
        ips = prompt_for_ips()
    elif args.ips:
        ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
    else:
        subnet = args.subnet or detect_local_subnet()
        if not subnet:
            print("[!] No pude detectar subred local; usa --subnet o --ips o --prompt.")
            sys.exit(1)
        print(f"[*] Subnet detectada: {subnet}")
        try:
            ips = generate_ips_from_subnet(subnet)
        except Exception as e:
            print("[!] Error construyendo lista de IPs:", e)
            sys.exit(1)

    # parse ports
    tcp_ports = DEFAULT_TCP_PORTS
    udp_ports = DEFAULT_UDP_PORTS
    if args.tcp_ports:
        tcp_ports = [int(x.strip()) for x in args.tcp_ports.split(",") if x.strip()]
    if args.udp_ports:
        udp_ports = [int(x.strip()) for x in args.udp_ports.split(",") if x.strip()]

    print(f"[*] IPs a procesar: {len(ips)}  | TCP puertos: {len(tcp_ports)}  | UDP puertos: {len(udp_ports)}")

    # descubrimiento: ping sweep + arp table
    alive = []
    print("[*] Ejecutando ping sweep (paralelo)...")
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                alive.append(ip)
    print(f"[*] Hosts con ping: {len(alive)}")

    # intentar ARP table para encontrar hosts adicionales y MACs
    arp_entries = arp_table_hosts()
    arp_ips = [e["ip"] for e in arp_entries]
    print(f"[*] Entradas ARP detectadas: {len(arp_entries)}")
    # Unir lists: uniq
    candidates = sorted(set(alive + arp_ips))
    if not candidates:
        print("[!] No se detectaron candidatos (ping ni arp). Salgo.")
        sys.exit(0)

    print(f"[*] Hosts candidatos finales: {len(candidates)}")

    results = {}
    # inicializar estructura
    for ip in candidates:
        mac = None
        for e in arp_entries:
            if e["ip"] == ip:
                mac = e.get("mac")
        results[ip] = {"ip": ip, "mac": mac, "alive": ip in alive, "tcp": [], "udp": [], "note": ""}

    # escaneo TCP (paralelo por host)
    print("[*] Escaneando TCP (connect) y banner grabbing...")
    def process_host_tcp(host):
        host_tcp = []
        for p in tcp_ports:
            open_flag = is_port_open_tcp(host, p, timeout=SOCKET_TIMEOUT)
            banner = ""
            src = []
            if open_flag:
                banner = grab_banner_tcp(host, p, timeout=SOCKET_TIMEOUT)
                src.append("tcp-connect")
            host_tcp.append({"port": p, "open": open_flag, "banner": banner, "source": src})
        return host_tcp

    with ThreadPoolExecutor(max_workers=min(args.threads, len(candidates))) as ex:
        futures = {ex.submit(process_host_tcp, ip): ip for ip in candidates}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host_tcp = fut.result()
            except Exception as e:
                host_tcp = []
            results[ip]["tcp"] = host_tcp
            open_count = len([p for p in host_tcp if p["open"]])
            print(f"[+] {ip} -> tcp abiertos: {open_count}")

    # escaneo UDP (opcional)
    if not args.no_udp:
        print("[*] Ejecutando probes UDP (puede fallar silenciosamente en muchos servicios)...")
        def process_host_udp(host):
            host_udp = []
            for p in udp_ports:
                ok, note = udp_probe(host, p, timeout=UDP_TIMEOUT)
                src = []
                if ok:
                    src.append("udp-probe")
                host_udp.append({"port": p, "open": ok, "note": str(note), "source": src})
            return host_udp

        with ThreadPoolExecutor(max_workers=min(60, len(candidates))) as ex:
            futures = {ex.submit(process_host_udp, ip): ip for ip in candidates}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    host_udp = fut.result()
                except Exception:
                    host_udp = []
                results[ip]["udp"] = host_udp
                udp_open = len([u for u in host_udp if u["open"]])
                if udp_open:
                    print(f"[+] {ip} -> udp responded on {udp_open} ports")

    # opcional: nmap como verificación
    nmap_out = {}
    if not args.no_nmap and shutil.which("nmap"):
        print("[*] Ejecutando nmap para verificación (esto puede tardar)...")
        # construir port spec simple: comma list of tcp ports
        port_spec = ",".join(str(p) for p in tcp_ports)
        nmap_out = run_nmap(candidates, port_spec, nmap_args="-sS -sV -Pn", out_xml="nmap_verify.xml")
        # integrar nmap results into results dict
        for host, ports in nmap_out.items():
            if host not in results:
                results[host] = {"ip": host, "mac": None, "alive": True, "tcp": [], "udp": [], "note": ""}
            # mark sources
            for p in ports:
                # find existing tcp entry and update
                found = False
                for e in results[host]["tcp"]:
                    if e["port"] == p["port"]:
                        e["open"] = (p["state"] == "open")
                        e["banner"] = (e.get("banner","") + " | nmap:" + p.get("service","") + " " + p.get("version","")).strip()
                        e["source"].append("nmap")
                        found = True
                        break
                if not found:
                    results[host]["tcp"].append({"port": p["port"], "open": (p["state"]=="open"), "banner":"nmap:"+p.get("service","")+" "+p.get("version",""), "source":["nmap"]})

    # finalizar: limpiar fuentes vacías y guardar
    for host, info in results.items():
        for p in info.get("tcp", []):
            if not p.get("source"):
                p["source"] = ["tcp-connect"] if p.get("open") else []
        for u in info.get("udp", []):
            if not u.get("source"):
                u["source"] = ["udp-probe"] if u.get("open") else []

    save_outputs(results, csvfile=args.out_csv, jsonfile=args.out_json)
    print("[*] Escaneo finalizado.")

if __name__ == "__main__":
    main()
