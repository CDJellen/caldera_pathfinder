import logging

import networkx as nx

from app.utility.base_world import BaseWorld
from plugins.pathfinder.app.objects.c_report import VulnerabilityReport
from plugins.pathfinder.app.interfaces.i_parser import ParserInterface


class ReportParser(ParserInterface):
    def __init__(self):
        self.format = 'caldera'
        self.log = logging.getLogger('caldera parser')

    def parse(self, report, name=None):
        try:
            caldera_report = BaseWorld.strip_yml(report)[0]
            return self.parse_caldera_report(root=caldera_report, name=name)
        except Exception as e:
            self.log.error('exception when loading caldera report: %s' % repr(e))
            return None

    def generate_network_map(self, report):
        if report.network_map_nodes and report.network_map_edges:
            return
        network_map = nx.Graph()
        for host1 in report.hosts.values():
            network_map.add_node(host1.ip)
            for host2 in report.hosts.values():
                if host2 != host1:
                    network_map.add_edge(host1.ip, host2.ip)
        report.network_map = network_map

    def generate_network_map_v2(self, report):
        if report.network_map_nodes and report.network_map_edges:
            return
        for host1 in report.hosts.keys():
            report.network_map_nodes.append(host1)
            for host2 in report.hosts.keys():
                if host2 != host1:
                    report.network_map_edges.append((host1, host2))

    def parse_caldera_report(self, root, name):
        root['name'] = name
        report = VulnerabilityReport.load(root)
        self.generate_network_map(report=report)
        self.generate_network_map_v2(report=report)
        return report
