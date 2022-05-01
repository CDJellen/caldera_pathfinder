import json
import logging

from plugins.pathfinder.app.objects.c_report import VulnerabilityReport
from plugins.pathfinder.app.objects.secondclass.c_host import Host
from plugins.pathfinder.app.objects.secondclass.c_port import Port
from plugins.pathfinder.app.interfaces.i_parser import ParserInterface


class ReportParser(ParserInterface):
    def __init__(self):
        self.format = 'siesta'
        self.log = logging.getLogger('siesta parser')

    def parse(self, report, name=None):
        try:
            with open(report, 'r') as f:
                siesta_report = json.load(f)
            caldera_report = self.parse_json_report(siesta_report, name)
            self.generate_network_map(caldera_report)
        except Exception as e:
            self.log.error('exception when parsing siesta report: %s' % repr(e))
            return None

        return caldera_report

    def parse_json_report(self, siesta_report, name):
        report = VulnerabilityReport(name=name)
        hosts = siesta_report['facts']['components']
        all_ports = siesta_report['facts']['ports']
        all_vulnerabilities = siesta_report['facts']['vulnerabilities']
        for h in hosts:
            host = Host(h['target'], hostname=h['host_name'])
            ports = [p for p in all_ports if p['target'] == host.ip]
            for p in ports:
                port = Port(
                    p['port_number'],
                    protocol=p['protocol'],
                    service=p['service'],
                    state=p['port_state'],
                )
                vulnerabilities = [
                    v
                    for v in all_vulnerabilities
                    if v['target'] == host.ip and v['port_number'] == port.number
                ]
                for v in vulnerabilities:
                    if v['severity'] != '0 - info':
                        port.cves.append(v['check_id'])
                        host.cves.append(v['check_id'])
                host.ports[port.number] = port
            report.hosts[host.ip] = host
        return report

    def generate_network_map(self, report):
        if report.network_map_nodes and report.network_map_edges:
            return
        for host1 in report.hosts.keys():
            report.network_map_nodes.append(host1)
            for host2 in report.hosts.keys():
                if host2 != host1:
                    report.network_map_edges.append((host1, host2))
