from PyQt5.QtWidgets import ( 
    QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, 
    QTableWidget, QTableWidgetItem
)
from utils.nucleo_scan import SuperScanner
from utils.superscanner import arp_table_hosts

class AppUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RedScanner - Analizador Automatizado de Red")

        layout = QVBoxLayout()
        self.label = QLabel("Bienvenido al Analizador Automatizado de Red")
        layout.addWidget(self.label)

        self.entry = QLineEdit()
        self.entry.setPlaceholderText("Introduce la subnet (ej: 192.168.1.0/24)")
        layout.addWidget(self.entry)

        self.table = QTableWidget()
        layout.addWidget(self.table)

        self.submit_button = QPushButton("Escanear")
        self.submit_button.clicked.connect(self.scan_network)
        layout.addWidget(self.submit_button)

        self.tcp_button = QPushButton("Escaneo TCP")
        self.tcp_button.clicked.connect(self.scan_tcp)
        layout.addWidget(self.tcp_button)

        self.udp_button = QPushButton("Escaneo UDP")
        self.udp_button.clicked.connect(self.scan_udp)
        layout.addWidget(self.udp_button)

        self.nmap_button = QPushButton("Verificación Nmap")
        self.nmap_button.clicked.connect(self.scan_nmap)
        layout.addWidget(self.nmap_button)

        self.rtsp_button = QPushButton("Fase RTSP")
        self.rtsp_button.clicked.connect(self.scan_rtsp)
        layout.addWidget(self.rtsp_button)

        self.heur_button = QPushButton("Heurística de cámaras")
        self.heur_button.clicked.connect(self.apply_heuristics)
        layout.addWidget(self.heur_button)

        self.save_button = QPushButton("Guardar resultados")
        self.save_button.clicked.connect(self.save_results)
        layout.addWidget(self.save_button)

        self.setLayout(layout)
        self.scanner = SuperScanner()
        self.results = {}

    def scan_network(self):
        subnet = self.entry.text().strip()
        if not subnet:
            return
        hosts = self.scanner.scan_subnet(subnet)
        # Obtener MACs de la tabla ARP local
        arp_map = {e["ip"]: e.get("mac", "") for e in arp_table_hosts()}
        for host in hosts:
            self.results[host] = {
                "ip": host,
                "mac": arp_map.get(host, ""),
                "alive": True,
                "tcp": [],
                "udp": [],
                "rtsp": [],
                "camera_score": 0,
                "camera_detected": False
            }
        self.show_hosts()

    def scan_tcp(self):
        hosts = list(self.results.keys())
        tcp_results = self.scanner.scan_tcp(hosts)
        for host in hosts:
            self.results[host]["tcp"] = tcp_results.get(host, [])
        self.show_tcp_results()

    def scan_udp(self):
        hosts = list(self.results.keys())
        udp_results = self.scanner.scan_udp(hosts)
        for host in hosts:
            self.results[host]["udp"] = udp_results.get(host, [])
        self.show_udp_results()

    def scan_nmap(self):
        hosts = list(self.results.keys())
        nmap_results = self.scanner.scan_nmap(hosts)
        # Integrar nmap en tcp
        for host in hosts:
            tcp_list = self.results[host].get("tcp", [])
            nmap_ports = nmap_results.get(host, [])
            for p in nmap_ports:
                tcp_list.append({
                    "port": p.get("port"),
                    "open": p.get("state") == "open",
                    "banner": f"nmap:{p.get('service','')} {p.get('version','')}",
                    "source": ["nmap"]
                })
            self.results[host]["tcp"] = tcp_list
        self.show_tcp_results()

    def scan_rtsp(self):
        hosts = list(self.results.keys())
        tcp_info = {host: self.results[host]["tcp"] for host in hosts}
        rtsp_results = self.scanner.scan_rtsp(hosts, tcp_info)
        for host in hosts:
            self.results[host]["rtsp"] = rtsp_results.get(host, [])
        self.show_rtsp_results()

    def apply_heuristics(self):
        for host, info in self.results.items():
            score, detected, reasons = self.scanner.apply_heuristics(
                info, [r for r in info.get("rtsp", []) if r.get("ok")]
            )
            info["camera_score"] = score
            info["camera_detected"] = detected
            info["camera_reasons"] = reasons
        self.show_heuristic_results()

    def save_results(self):
        self.scanner.save(self.results, "resultados_scaner.csv", "resultados_scaner.json")

    def show_hosts(self):
        self.table.clear()
        self.table.setRowCount(len(self.results))
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Host", "MAC", "Alive"])
        for row, (host, info) in enumerate(self.results.items()):
            self.table.setItem(row, 0, QTableWidgetItem(str(host)))
            self.table.setItem(row, 1, QTableWidgetItem(str(info.get("mac", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(str(info.get("alive", True))))
        self.table.resizeColumnsToContents()

    def show_tcp_results(self):
        # Mostrar todos los puertos TCP abiertos y banners
        rows = []
        for host, info in self.results.items():
            for port_info in info.get("tcp", []):
                rows.append((host, port_info.get("port", ""), port_info.get("open", ""), port_info.get("banner", "")))
        self.table.clear()
        self.table.setRowCount(len(rows))
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Host", "Puerto", "Abierto", "Banner"])
        for row, (host, port, open_, banner) in enumerate(rows):
            self.table.setItem(row, 0, QTableWidgetItem(str(host)))
            self.table.setItem(row, 1, QTableWidgetItem(str(port)))
            self.table.setItem(row, 2, QTableWidgetItem(str(open_)))
            self.table.setItem(row, 3, QTableWidgetItem(str(banner)))
        self.table.resizeColumnsToContents()

    def show_udp_results(self):
        rows = []
        for host, info in self.results.items():
            for port_info in info.get("udp", []):
                rows.append((host, port_info.get("port", ""), port_info.get("open", ""), port_info.get("note", "")))
        self.table.clear()
        self.table.setRowCount(len(rows))
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Host", "Puerto", "Abierto", "Nota"])
        for row, (host, port, open_, note) in enumerate(rows):
            self.table.setItem(row, 0, QTableWidgetItem(str(host)))
            self.table.setItem(row, 1, QTableWidgetItem(str(port)))
            self.table.setItem(row, 2, QTableWidgetItem(str(open_)))
            self.table.setItem(row, 3, QTableWidgetItem(str(note)))
        self.table.resizeColumnsToContents()

    def show_nmap_results(self, nmap_results):
        self.table.clear()
        self.table.setRowCount(len(nmap_results))
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Host", "Puerto", "Estado", "Servicio"])
        row = 0
        for host, ports in nmap_results.items():
            for port_info in ports:
                self.table.setItem(row, 0, QTableWidgetItem(str(host)))
                self.table.setItem(row, 1, QTableWidgetItem(str(port_info.get("port", ""))))
                self.table.setItem(row, 2, QTableWidgetItem(str(port_info.get("state", ""))))
                self.table.setItem(row, 3, QTableWidgetItem(str(port_info.get("service", ""))))
                row += 1
        self.table.resizeColumnsToContents()

    def show_rtsp_results(self):
        rows = []
        for host, info in self.results.items():
            for url_info in info.get("rtsp", []):
                rows.append((host, url_info.get("port", ""), url_info.get("url", ""), url_info.get("ok", False)))
        self.table.clear()
        self.table.setRowCount(len(rows))
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Host", "Puerto", "RTSP URL", "OK"])
        for row, (host, port, url, ok) in enumerate(rows):
            self.table.setItem(row, 0, QTableWidgetItem(str(host)))
            self.table.setItem(row, 1, QTableWidgetItem(str(port)))
            self.table.setItem(row, 2, QTableWidgetItem(str(url)))
            self.table.setItem(row, 3, QTableWidgetItem(str(ok)))
        self.table.resizeColumnsToContents()

    def show_heuristic_results(self):
        self.table.clear()
        self.table.setRowCount(len(self.results))
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Host", "MAC", "Cámara Detectada", "Score", "Razones"])
        for row, (host, info) in enumerate(self.results.items()):
            self.table.setItem(row, 0, QTableWidgetItem(str(host)))
            self.table.setItem(row, 1, QTableWidgetItem(str(info.get("mac", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(str(info.get("camera_detected", ""))))
            self.table.setItem(row, 3, QTableWidgetItem(str(info.get("camera_score", ""))))
            self.table.setItem(row, 4, QTableWidgetItem(", ".join(info.get("camera_reasons", []))))
        self.table.resizeColumnsToContents()

    def clear_table(self):
        self.table.clear()
        self.table.setRowCount(0)
        self.table.setColumnCount(0)