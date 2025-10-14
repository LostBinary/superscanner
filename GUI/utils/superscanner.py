#!/usr/bin/env python3
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
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

# ---------------- Config general ----------------
DEFAULT_TCP_PORTS = [21,22,23,25,53,80,81,88,110,111,123,135,137,138,139,143,161,179,389,443,445,554,631,636,8000,8080,8443,8554,9000,9090,37777,5000]
DEFAULT_UDP_PORTS = [53,67,68,69,123,161,500,4500]
RTSP_PORTS_TO_TRY = [554,8554,80,8080,8000,37777,5000]
RTSP_PATTERNS = [
    "/",
    "/stream",
    "/stream1",
    "/h264",
    "/ch0_0.h264",
    "/live",
    "/live.sdp",
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/media.smp",
    "/videoMain",
    "/video1",
    "/0",
    "/1",
]
RTSP_CREDENTIALS = [
    ("", ""),
    ("admin","admin"),
    ("admin","123456"),
    ("admin","888888"),
    ("admin","000000"),
    ("root","root"),
    ("user","user"),
]
SOCKET_TIMEOUT = 1.0
UDP_TIMEOUT = 1.0
PING_TIMEOUT = 1
MAX_THREADS = 20
OUT_CSV = "resultados_scaner.csv"
OUT_JSON = "resultados_scaner.json"
# -------------------------------------------------

def detect_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(local_ip + "/24", strict=False))
    except Exception:
        return None

def run_cmd(cmd, timeout=5):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, shell=False)
        return proc.returncode, proc.stdout.decode(errors="ignore"), proc.stderr.decode(errors="ignore")
    except Exception as e:
        return 1, "", str(e)

def ping_host(ip):
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT*1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip]
    rc, _, _ = run_cmd(cmd, timeout=PING_TIMEOUT+1)
    return rc == 0

def arp_table_hosts():
    # parse 'arp -a' output
    try:
        rc, out, err = run_cmd(["arp", "-a"], timeout=3)
    except Exception:
        return []
    entries = []
    if not out:
        return entries
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        ip = None
        mac = None
        parts = line.split()
        for p in parts:
            if p.startswith("(") and p.endswith(")"):
                ip = p.strip("()")
            if (":" in p or "-" in p) and len(p) >= 7:
                mac = p.replace("-", ":")
        if not ip:
            # try windows format like '192.168.1.1           00-11-22-33-44-55   dynamic'
            for p in parts:
                if p.count(".") == 3 and len(p) <= 15:
                    ip = p
        if ip:
            entries.append({"ip": ip, "mac": mac, "raw": line})
    return entries

def is_port_open_tcp(host, port, timeout=SOCKET_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def grab_banner_tcp(host, port, timeout=SOCKET_TIMEOUT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if port in (80,8080,8000,8443,554):
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
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt = b"\x00"
        try:
            sock.sendto(pkt, (host, port))
        except Exception:
            sock.close()
            return False, "send-failed"
        try:
            data, addr = sock.recvfrom(2048)
            sock.close()
            return True, f"recv_len={len(data)}"
        except socket.timeout:
            sock.close()
            return False, "no-reply"
        except Exception as e:
            sock.close()
            return False, f"err:{e}"
    except Exception as e:
        return False, f"err:{e}"

def run_nmap(hosts, port_spec, nmap_args="-sS -sV -Pn", out_xml="nmap_verif.xml"):
    if not shutil.which("nmap"):
        return {}
    hosts_str = " ".join(hosts)
    cmd = f"nmap {nmap_args} -p {port_spec} -oX {out_xml} {hosts_str}"
    print("[*] Ejecutando nmap:", cmd)
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    except subprocess.TimeoutExpired:
        print("[!] nmap timeout")
        return {}
    results = {}
    try:
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
                    ver = serv.get("product","") + " " + serv.get("version","")
                ports.append({"port": pid, "state": state, "service": svc, "version": ver})
            results[addr] = ports
    except Exception as e:
        print("[!] Error parsing nmap XML:", e)
    return results

# ---------------- RTSP / ffprobe ----------------
def try_ffprobe(url, timeout=5):
    """Return (ok:bool, note:str). Requires ffprobe in PATH."""
    if not shutil.which("ffprobe"):
        return False, "ffprobe-not-found"
    try:
        cmd = ["ffprobe", "-v", "error", "-timeout", str(int(timeout*1000000)), "-rtsp_transport", "tcp", "-i", url]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout+2)
        stderr = proc.stderr.decode(errors="ignore")
        ok = proc.returncode == 0 or ("Stream" in stderr) or ("Input" in stderr) or ("Video:" in stderr)
        return ok, stderr.strip().replace("\n"," ")[:600]
    except Exception as e:
        return False, str(e)

def build_rtsp_urls_for_host(host, ports):
    urls = []
    for port in ports:
        for p in RTSP_PATTERNS:
            if port == 554:
                urls.append(f"rtsp://{host}{p}")
            urls.append(f"rtsp://{host}:{port}{p}")
    return urls

def scan_rtsp_host(host, ports_to_try=None, creds=RTSP_CREDENTIALS, timeout=5, max_workers=6):
    ports = ports_to_try or RTSP_PORTS_TO_TRY
    urls = build_rtsp_urls_for_host(host, ports)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {}
        for url in urls:
            for user, pwd in creds:
                if user or pwd:
                    full = url.replace("rtsp://", f"rtsp://{user}:{pwd}@")
                else:
                    full = url
                futures[ex.submit(try_ffprobe, full, timeout)] = (full, user, pwd)
        for fut in as_completed(futures):
            full, user, pwd = futures[fut]
            try:
                ok, note = fut.result()
            except Exception as e:
                ok, note = False, str(e)
            results.append({"host": host, "url": full, "user": user, "pass": pwd, "ok": ok, "note": note})
            if ok:
                # stop early on first success for host
                return results
    return results

# --------------- Heurística para detectar cámaras ---------------
CAMERA_KEYWORDS = ["onvif","camera","ipcam","h.264","h264","rtsp","dahua","hikvision","ipc","video","surveillance","nv12","g711","g726"]

def heuristic_is_camera(host_info, rtsp_hits):
    score = 0
    reasons = []
    # puertos de interes
    tcp_open_ports = [p["port"] for p in host_info.get("tcp",[]) if p.get("open")]
    if any(p in tcp_open_ports for p in (554,8554,37777,5000,80,8080)):
        score += 3
        reasons.append("puertos-rtsp/http detectados")
    # banners
    banners = " ".join([p.get("banner","") or "" for p in host_info.get("tcp",[])])
    if any(k.lower() in banners.lower() for k in CAMERA_KEYWORDS):
        score += 3
        reasons.append("banner contiene keywords de cámara")
    # mac OUI heuristico
    mac = host_info.get("mac") or ""
    if mac and len(mac.split(":")[0])==2:
        # not a reliable check here, but could add OUI DB later
        pass
    # RTSP hits
    if rtsp_hits:
        score += 5
        reasons.append("rtsp-responds")
    detected = score >= 4
    return score, detected, reasons

# ---------------- I/O save ----------------
def save_results(results_dict, csvfile=OUT_CSV, jsonfile=OUT_JSON):
    rows = []
    for host, info in results_dict.items():
        base = {"host": host, "mac": info.get("mac",""), "alive": info.get("alive", False), "camera_score": info.get("camera_score",0), "camera_detected": info.get("camera_detected", False)}
        # tcp
        for t in info.get("tcp", []):
            r = base.copy()
            r.update({"proto":"tcp","port":t["port"], "open": t.get("open", False), "banner": t.get("banner",""), "sources": ",".join(t.get("source",[]))})
            rows.append(r)
        # udp
        for u in info.get("udp", []):
            r = base.copy()
            r.update({"proto":"udp","port":u["port"], "open": u.get("open", False), "banner": u.get("note",""), "sources": ",".join(u.get("source",[]))})
            rows.append(r)
        # if none
        if not info.get("tcp") and not info.get("udp"):
            r = base.copy()
            r.update({"proto":"","port":"","open":"","banner":"","sources":""})
            rows.append(r)
    # write csv
    with open(csvfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host","mac","alive","camera_score","camera_detected","proto","port","open","banner","sources"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    # write json
    with open(jsonfile, "w", encoding="utf-8") as f:
        json.dump(results_dict, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved CSV: {csvfile} and JSON: {jsonfile}")

# ----------------- Pipeline functions -----------------
def discover_hosts_from_subnet(subnet, threads=MAX_THREADS):
    ips = []
    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses > 4096:
        raise ValueError("Network too large; choose smaller range.")
    print(f"[*] Doing ping sweep on {subnet} ...")
    with ThreadPoolExecutor(max_workers=min(threads, 200)) as ex:
        futures = {ex.submit(ping_host, str(ip)): str(ip) for ip in net.hosts()}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                ips.append(ip)
    return ips

def scan_tcp_and_banners(hosts, tcp_ports, threads=40):
    results = {}
    def scan_host_tcp(host):
        host_tcp = []
        for p in tcp_ports:
            ok = is_port_open_tcp(host, p, timeout=SOCKET_TIMEOUT)
            banner = ""
            sources = []
            if ok:
                banner = grab_banner_tcp(host, p, timeout=SOCKET_TIMEOUT)
                sources.append("tcp-connect")
            host_tcp.append({"port": p, "open": ok, "banner": banner, "source": sources})
        return host_tcp
    with ThreadPoolExecutor(max_workers=min(threads, len(hosts) or 1)) as ex:
        futures = {ex.submit(scan_host_tcp, h): h for h in hosts}
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                tcp_res = fut.result()
            except Exception:
                tcp_res = []
            results[h] = tcp_res
            open_count = len([x for x in tcp_res if x["open"]])
            print(f"[+] {h}: TCP abiertos: {open_count}")
    return results

def scan_udp_hosts(hosts, udp_ports, threads=40):
    results = {}
    def scan_host_udp(host):
        host_udp = []
        for p in udp_ports:
            ok, note = udp_probe(host, p, timeout=UDP_TIMEOUT)
            src = ["udp-probe"] if ok else []
            host_udp.append({"port": p, "open": ok, "note": note, "source": src})
        return host_udp
    with ThreadPoolExecutor(max_workers=min(threads, len(hosts) or 1)) as ex:
        futures = {ex.submit(scan_host_udp, h): h for h in hosts}
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                udp_res = fut.result()
            except Exception:
                udp_res = []
            results[h] = udp_res
            opens = len([u for u in udp_res if u["open"]])
            if opens:
                print(f"[+] {h}: UDP responde en puertos : {opens}")
    return results

def rtsp_phase_over_hosts(hosts, tcp_info_dict, timeout=5, max_workers=6):
    all_rtsp_hits = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts) or 1)) as ex:
        futures = {ex.submit(scan_rtsp_host, h, None, RTSP_CREDENTIALS, timeout, max_workers): h for h in hosts}
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = [{"host": h, "url": "", "user":"", "pass":"", "ok": False, "note": str(e)}]
            hits = [r for r in res if r.get("ok")]
            all_rtsp_hits[h] = res
            if hits:
                print(f"[HIT-RTSP] {h} -> {hits[0]['url']} creds=({hits[0]['user']}:{hits[0]['pass']})")
    return all_rtsp_hits

# ---------------- Interactive menu ----------------
def interactive_menu(state):
    menu = """
=== NETWORK SCANNER - MENU INTERACTIVO ===
1) Descubrir hosts por subnet (ping sweep)
2) Añadir IPs manualmente (prompt)
3) Cargar hosts desde subnet automática detectada
4) Ejecutar escaneo TCP + banners
5) Ejecutar probes UDP
6) Ejecutar nmap (verificación)
7) Ejecutar fase RTSP (ffprobe)
8) Ejecutar heurística de detección de cámaras (auto)
9) Guardar resultados (CSV/JSON)
10) Mostrar resumen en pantalla
11) Ejecutar pipeline completo (discover -> tcp -> udp -> nmap -> rtsp -> heur)
q) Salir
-----------------------------------------------------------------
== Búsqueda de host ocultos y análisis detallado ==
a) Búsqueda intensiva de host
b) Análisis detallado de puertos abiertos
c) Búsqueda por MAC
q) Salir
Elige opción: """
    while True:
        choice = input(menu).strip()
        if choice == "q":
            print("Saliendo...")
            break
        elif choice == "1":
            subnet = input("Introduce subnet CIDR (ej: 192.168.1.0/24): ").strip()
            ips = discover_hosts_from_subnet(subnet)
            print(f"[=] Encontrados {len(ips)} hosts vivos.")
            state["ips"] = ips
        elif choice == "2":
            s = input("Introduce IPs separadas por coma: ").strip()
            ips = [ip.strip() for ip in s.split(",") if ip.strip()]
            state.setdefault("ips", [])
            state["ips"].extend(ips)
            state["ips"] = sorted(set(state["ips"]))
            print(f"[=] Hosts totales: {len(state['ips'])}")
        elif choice == "3":
            detected = detect_local_subnet()
            if not detected:
                print("[!] No se pudo detectar subred automáticamente.")
            else:
                print(f"Subred detectada: {detected}")
                ips = discover_hosts_from_subnet(detected)
                state["ips"] = ips
                print(f"[=] Hosts vivos: {len(ips)}")
        elif choice == "4":
            if not state.get("ips"):
                print("[!] No hay IPs. Añade o descubre hosts primero.")
                continue
            tcp_ports_str = input(f"Puertos TCP a probar (coma-sep) [enter=default {DEFAULT_TCP_PORTS[:10]}...]: ").strip()
            tcp_ports = DEFAULT_TCP_PORTS if not tcp_ports_str else [int(x) for x in tcp_ports_str.split(",") if x.strip()]
            tcp_results = scan_tcp_and_banners(state["ips"], tcp_ports)
            # init state.results
            state.setdefault("results", {})
            for h, tcp in tcp_results.items():
                state["results"].setdefault(h, {"ip":h, "mac":None, "alive":True, "tcp":[], "udp":[], "rtsp":[], "camera_score":0, "camera_detected":False})
                state["results"][h]["tcp"] = tcp
            print("[=] Escaneo TCP OK.")
        elif choice == "5":
            if not state.get("ips"):
                print("[!] No hay IPs. Añade o descubre hosts primero.")
                continue
            udp_ports_str = input(f"Puertos UDP a probar (coma-sep) [enter=default {DEFAULT_UDP_PORTS}]: ").strip()
            udp_ports = DEFAULT_UDP_PORTS if not udp_ports_str else [int(x) for x in udp_ports_str.split(",") if x.strip()]
            udp_results = scan_udp_hosts(state["ips"], udp_ports)
            state.setdefault("results", {})
            for h, udp in udp_results.items():
                state["results"].setdefault(h, {"ip":h, "mac":None, "alive":True, "tcp":[], "udp":[], "rtsp":[], "camera_score":0, "camera_detected":False})
                state["results"][h]["udp"] = udp
            print("[=] UDP probes OK.")
        elif choice == "6":
            if not state.get("ips"):
                print("[!] No hay IPs. Añade o descubre hosts primero.")
                continue
            if not shutil.which("nmap"):
                print("[!] nmap no está instalado o no está en PATH. Instálalo para usar esta opción.")
                continue
            port_spec = input("Especifica puerto(s) para nmap (ej: 80,554 o 1-65535): ").strip()
            if not port_spec:
                port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
            nmap_res = run_nmap(state["ips"], port_spec)
            state.setdefault("results", {})
            for h, ports in nmap_res.items():
                state["results"].setdefault(h, {"ip":h, "mac":None, "alive":True, "tcp":[], "udp":[], "rtsp":[], "camera_score":0, "camera_detected":False})
                # integrate nmap ports
                for p in ports:
                    # append or update
                    state["results"][h]["tcp"].append({"port": p["port"], "open": (p["state"]=="open"), "banner": f"nmap:{p.get('service','')} {p.get('version','')}".strip(), "source":["nmap"]})
            print("[=] nmap verificacion OK.")
        elif choice == "7":
            if not state.get("results"):
                print("[!] Ejecuta al menos el TCP scan (opción 4) o añade hosts.")
                continue
            hosts = list(state["results"].keys())
            rtsp_hits = rtsp_phase_over_hosts(hosts, {h: state["results"][h].get("tcp",[]) for h in hosts})
            for h, res in rtsp_hits.items():
                state["results"].setdefault(h, {"ip":h})
                state["results"][h]["rtsp"] = res
            print("[=] Fase RTSP OK.")
        elif choice == "8":
            if not state.get("results"):
                print("[!] Ejecuta fases anteriores primero.")
                continue
            for h, info in state["results"].items():
                score, detected, reasons = heuristic_is_camera(info, [r for r in info.get("rtsp",[]) if r.get("ok")])
                info["camera_score"] = score
                info["camera_detected"] = detected
                info["camera_reasons"] = reasons
            print("[=] Heurística aplicada. Revisa el estado o guarda.")
        elif choice == "9":
            outcsv = input(f"CSV en [{OUT_CSV}]: ").strip() or OUT_CSV
            outjson = input(f"JSON en [{OUT_JSON}]: ").strip() or OUT_JSON
            save_results(state.get("results", {}), csvfile=outcsv, jsonfile=outjson)
        elif choice == "10":
            # print summary
            res = state.get("results", {})
            for h, info in res.items():
                opens = [p["port"] for p in info.get("tcp",[]) if p.get("open")]
                rtsp_ok = [r for r in info.get("rtsp",[]) if r.get("ok")]
                print(f"- {h} | alive={info.get('alive')} tcp_open={opens} rtsp_hits={len(rtsp_ok)} camera_detected={info.get('camera_detected')}")
        elif choice == "11":
            print("[*] Ejecutando pipeline completo...")
            # discover if not present
            if not state.get("ips"):
                subnet = detect_local_subnet()
                if not subnet:
                    print("[!] No se detectó subred local; añade ips o usa prompt.")
                    continue
                state["ips"] = discover_hosts_from_subnet(subnet)
            # tcp
            tcp_res = scan_tcp_and_banners(state["ips"], DEFAULT_TCP_PORTS)
            state["results"] = {}
            arp_entries = arp_table_hosts()
            mac_map = {e["ip"]: e.get("mac") for e in arp_entries}
            for h, tcp in tcp_res.items():
                state["results"][h] = {"ip":h, "mac": mac_map.get(h), "alive": True, "tcp": tcp, "udp": [], "rtsp": [], "camera_score":0, "camera_detected":False}
            # udp
            udp_res = scan_udp_hosts(state["ips"], DEFAULT_UDP_PORTS)
            for h, udp in udp_res.items():
                state["results"].setdefault(h, {"ip":h})
                state["results"][h]["udp"] = udp
            # nmap
            if shutil.which("nmap"):
                print("[*] Ejecutando nmap (verificación)...")
                port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
                nmap_out = run_nmap(list(state["results"].keys()), port_spec)
                for h, ports in nmap_out.items():
                    for p in ports:
                        state["results"][h]["tcp"].append({"port": p["port"], "open": (p["state"]=="open"), "banner": f"nmap:{p.get('service','')} {p.get('version','')}", "source":["nmap"]})
            # rtsp
            hosts = list(state["results"].keys())
            rtsp_out = rtsp_phase_over_hosts(hosts, {h: state["results"][h].get("tcp",[]) for h in hosts})
            for h, arr in rtsp_out.items():
                state["results"][h]["rtsp"] = arr
            # heuristics
            for h, info in state["results"].items():
                score, detected, reasons = heuristic_is_camera(info, [r for r in info.get("rtsp",[]) if r.get("ok")])
                info["camera_score"] = score
                info["camera_detected"] = detected
                info["camera_reasons"] = reasons
            print("[=] Pipeline completo ejecutado.")
        elif choice == "a":  
            print("Opción en desarrollo...")
        elif choice == "b":
            print("Opción en desarrollo...")
        elif choice == "c":
            print("Opción en desarrollo...")
        else:
            print("[!] Opción no válida.")

# ------------------ Main CLI runner ------------------
def main():
    parser = argparse.ArgumentParser(description="Network Super Scanner (interactivo + rtsp + heuristica).")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--subnet", help="CIDR a escanear (ex: 192.168.1.0/24). Si se omite, auto-detectara /24.")
    group.add_argument("--ips", help="Separadas por coma")
    parser.add_argument("--ip", action="store_true", help="Prompt para IPs.")
    parser.add_argument("--i", action="store_true", help="Carga Menu CLI (Interfaz consola)")
    parser.add_argument("--no-udp", action="store_true", help="Salta UDP probes.")
    parser.add_argument("--no-nmap", action="store_true", help="Salta nmap.")
    parser.add_argument("--ffprobe-timeout", type=float, default=5.0, help="Cuanto tiempo (s) para intentos de ffprobe.")
    parser.add_argument("--out-csv", default=OUT_CSV)
    parser.add_argument("--out-json", default=OUT_JSON)
    args = parser.parse_args()

    state = {}
    # build initial IP list
    ips = []
    if args.ip:
        s = input("Introduce IPs (coma-sep): ").strip()
        ips = [ip.strip() for ip in s.split(",") if ip.strip()]
    elif args.ips:
        ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]
    else:
        subnet = args.subnet or detect_local_subnet()
        if not subnet:
            print("[!] No pude detectar subred local. Usa --subnet, --ips o --ip.")
            # still allow interactive
            if args.i:
                state["ips"] = []
                interactive_menu(state)
                print("\n")
                print("\n")
                save_results(state.get("results", {}), csvfile=args.out_csv, jsonfile=args.out_json)
                return
            sys.exit(1)
        print(f"[*] Subnet: {subnet}")
        ips = discover_hosts_from_subnet(subnet)

    state["ips"] = ips
    print(f"[*] Candidato para Host inicial: {len(ips)}")

    if args.i:
        interactive_menu(state)
        print("\n")
        print("\n")
        save_results(state.get("results", {}), csvfile=args.out_csv, jsonfile=args.out_json)
        return

    # Non-interactive pipeline: tcp -> udp -> nmap (optional) -> rtsp -> heuristics
    results = {}
    arp_entries = arp_table_hosts()
    mac_map = {e["ip"]: e.get("mac") for e in arp_entries}

    tcp_map = scan_tcp_and_banners(state["ips"], DEFAULT_TCP_PORTS)
    for h, tcp in tcp_map.items():
        results[h] = {"ip":h, "mac": mac_map.get(h), "alive": True, "tcp": tcp, "udp": [], "rtsp": [], "camera_score":0, "camera_detected":False}

    if not args.no_udp:
        udp_map = scan_udp_hosts(state["ips"], DEFAULT_UDP_PORTS)
        for h, udp in udp_map.items():
            results[h]["udp"] = udp

    # nmap optional
    if not args.no_nmap and shutil.which("nmap"):
        print("[*] Verificando resultados con nmap...")
        port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
        nmap_out = run_nmap(list(results.keys()), port_spec)
        for h, ports in nmap_out.items():
            for p in ports:
                results[h]["tcp"].append({"port": p["port"], "open": (p["state"]=="open"), "banner": f"nmap:{p.get('service','')} {p.get('version','')}", "source":["nmap"]})

    # RTSP phase
    hosts = list(results.keys())
    rtsp_out = rtsp_phase_over_hosts(hosts, {h: results[h].get("tcp",[]) for h in hosts}, timeout=args.ffprobe_timeout)
    for h, arr in rtsp_out.items():
        results[h]["rtsp"] = arr

    # heuristics
    for h, info in results.items():
        score, detected, reasons = heuristic_is_camera(info, [r for r in info.get("rtsp",[]) if r.get("ok")])
        info["camera_score"] = score
        info["camera_detected"] = detected
        info["camera_reasons"] = reasons

    save_results(results, csvfile=args.out_csv, jsonfile=args.out_json)
    print("[*] OK. Revisa informes y examina host con camera_detected=True con cuidado.")

if __name__ == "__main__":
    main()

