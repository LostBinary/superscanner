from utils.superscanner import ( discover_hosts_from_subnet, scan_tcp_and_banners, 
                                scan_udp_hosts, run_nmap, rtsp_phase_over_hosts, 
                                heuristic_is_camera, save_results, 
                                DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS
                                )

class SuperScanner:
    def scan_subnet(self, subnet):
        return discover_hosts_from_subnet(subnet)

    def scan_tcp(self, hosts):
        return scan_tcp_and_banners(hosts, DEFAULT_TCP_PORTS)

    def scan_udp(self, hosts):
        return scan_udp_hosts(hosts, DEFAULT_UDP_PORTS)

    def scan_nmap(self, hosts):
        port_spec = ",".join(str(p) for p in DEFAULT_TCP_PORTS)
        return run_nmap(hosts, port_spec)

    def scan_rtsp(self, hosts, tcp_info_dict):
        return rtsp_phase_over_hosts(hosts, tcp_info_dict)

    def apply_heuristics(self, host_info, rtsp_hits):
        return heuristic_is_camera(host_info, rtsp_hits)

    def save(self, results_dict, csvfile, jsonfile):
        save_results(results_dict, csvfile, jsonfile)