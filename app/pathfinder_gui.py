import os
import copy
import glob
import yaml
import logging
import asyncio
from aiohttp import web
from aiohttp_jinja2 import template
from datetime import date
from importlib import import_module

from app.service.auth_svc import for_all_public_methods, check_authorization
from app.utility.base_world import BaseWorld
from plugins.pathfinder.app.pathfinder_svc import PathfinderService
from plugins.pathfinder.app.pathfinder_util import sanitize_filename
from plugins.pathfinder.app.objects.secondclass.c_host import Ability
import plugins.pathfinder.settings as settings


@for_all_public_methods(check_authorization)
class PathfinderGUI(BaseWorld):
    def __init__(self, services, name, description, installed_dependencies):
        self.name = name
        self.description = description
        self.services = services
        self.installed_dependencies = installed_dependencies
        self.auth_svc = services.get('auth_svc')
        self.log = logging.getLogger('pathfinder_gui')
        self.file_svc = services.get('file_svc')
        self.data_svc = services.get('data_svc')
        self.loop = asyncio.get_event_loop()
        self.running_scans = dict()
        self.scanners = dict()
        self.pathfinder_svc = PathfinderService(services)

    async def _get_access(self, request):
        return dict(access=tuple(await self.auth_svc.get_permissions(request)))

    @template('pathfinder.html')
    async def splash(self, request):
        reports = [
            vr.display
            for vr in await self.data_svc.locate(
                'vulnerabilityreports', match=await self._get_access(request)
            )
        ]
        loaded_scanners = await self.load_scanners()
        self.scanners = loaded_scanners
        return dict(
            name=self.name,
            description=self.description,
            scanners=list(loaded_scanners.keys()),
            input_parsers=list(self.pathfinder_svc.parsers.keys()),
            vulnerability_reports=reports,
        )

    @check_authorization
    @template('graph.html')
    async def graph(self, request):
        requested_report = request.query.get('report')
        data = await self.build_visualization_dataset(requested_report)
        return dict(report_data=data)

    async def build_visualization_dataset(self, report):
        visualization_data = dict(nodes=[], links=[])
        vr = await self.data_svc.locate('vulnerabilityreports', match=dict(id=report))
        if not vr:
            return visualization_data

        scanner_node = 'scanner'
        visualization_data['nodes'].append(
            dict(id=scanner_node, label='scanner', group='scanners')
        )
        for ip, host in vr[0].hosts.items():
            visualization_data['nodes'].append(dict(id=ip, label=ip, group='hosts'))
            for pnum, port in {
                pn: p for pn, p in host.ports.items() if p.state == 'open'
            }.items():
                id = '%s:%s' % (ip, pnum)
                visualization_data['nodes'].append(
                    dict(id=id, label=pnum, group='ports')
                )
                visualization_data['links'].append(
                    dict(source=ip, target=id, type='port')
                )
                for cve in port.cves:
                    id2 = '%s:%s' % (id, cve)
                    dim = (
                        False
                        if await self.pathfinder_svc.collect_tagged_abilities([cve])
                        != []
                        else True
                    )
                    visualization_data['nodes'].append(
                        dict(id=id2, label=cve, group='cves', dim=dim)
                    )
                    visualization_data['links'].append(
                        dict(source=id, target=id2, type='cve')
                    )

        for edge in vr[0].network_map_edges:
            visualization_data['links'].append(
                dict(source=edge[0], target=edge[1], type='network')
            )

        return visualization_data

    @check_authorization
    async def pathfinder_core(self, request):
        try:
            data = dict(await request.json())
            index = data.pop('index')
            options = dict(
                DELETE=dict(report=lambda d: self.delete_report(d)),
                PUT=dict(),
                POST=dict(
                    scan=lambda d: self.scan(d),
                    import_scan=lambda d: self.import_report(d),
                    reports=lambda d: self.retrieve_reports(),
                    status=lambda d: self.check_scan_status(),
                    create_adversary=lambda d: self.generate_adversary(d),
                    scanner_config=lambda d: self.return_scanner_configuration(d),
                    source_name=lambda d: self.get_source_name(d),
                    host_info=lambda d: self.retrieve_hosts_from_report(d),
                    update_host=lambda d: self.update_host_in_report(d),
                    paths=lambda d: self.get_paths(d),
                    paths_v2=lambda d: self.get_paths_v2(d),
                    create_adversary_v2=lambda d: self.generate_adversary_v2(d),
                    edge_info=lambda d: self.retrieve_edges_from_report(d),
                    update_edges=lambda d: self.update_report_edges(d),
                ),
                PATCH=dict(report=lambda d: self.rename_report(d)),
            )
            if index not in options[request.method]:
                return web.HTTPBadRequest(
                    text='index: %s is not a valid index for the pathfinder plugin'
                    % index
                )
            return web.json_response(await options[request.method][index](data))
        except Exception as e:
            self.log.error(repr(e), exc_info=True)

    async def scan(self, data):
        scanner = data.pop('scanner', None)
        fields = data.pop('fields', None)
        filename = fields.pop('filename') or sanitize_filename(
            f'pathfinder_{date.today().strftime("%b-%d-%Y")}'
        )
        filename = filename.replace(' ', '_')
        report_file = f'{settings.data_dir}/reports/{filename}.xml'
        try:
            loaded_scanner = await self.load_scanner(scanner)
            scan = loaded_scanner.Scanner(
                filename=report_file, dependencies=self.installed_dependencies, **fields
            )
            self.running_scans[scan.id] = scan
            self.loop.create_task(scan.scan())
            return dict(
                status='pass',
                id=scan.id,
                output='scan initiated, depending on scope it may take a few minutes',
            )
        except Exception as e:
            self.log.error(repr(e), exc_info=True)
            return dict(status='fail', output='exception occurred while starting scan')

    async def import_report(self, data):
        scan_type = data.get('format')
        report_name = data.get('filename')
        source = await self.pathfinder_svc.import_scan(scan_type, report_name)
        if source:
            return dict(
                status='pass', output='source: %s' % source.name, source=source.id
            )
        return dict(
            status='fail',
            output='failure occurred during report importing, please check server logs',
        )

    async def rename_report(self, data):
        try:
            report_id = data.get('id')
            report = await self.data_svc.locate(
                'vulnerabilityreports', match=dict(id=report_id)
            )
            report = report[0]
            report.name = data.get('rename')
            await self.data_svc.remove('vulnerabilityreports', match=dict(id=report_id))
            await self.data_svc.store(report)
            return dict(status='success')
        except Exception as e:
            self.log.error(repr(e), exc_info=True)
            return dict(
                status='fail', output='exception occurred while patching report'
            )

    async def delete_report(self, data):
        try:
            report_id = data.get('id')
            await self.data_svc.remove('vulnerabilityreports', match=dict(id=report_id))
            return dict(status='success')
        except Exception as e:
            self.log.error(repr(e), exc_info=True)
            return dict(
                status='fail', output='exception occurred while removing report'
            )

    async def retrieve_reports(self):
        reports = [
            vr.display for vr in await self.data_svc.locate('vulnerabilityreports')
        ]
        return dict(reports=reports)

    async def retrieve_hosts_from_report(self, data: dict) -> dict:
        """Use id provided by the request, return info on hosts in the report.

        Args:
            data: The HTTP request data, assumed to contain an `id` which maps
                  to a vulnerability report in the data service.

        Returns:
            The response status (`'success'` or `'fail'`) as well as a list of
            dictionaries describing each host for the matching vulnerability
            report.
        """
        report_id = data.get('id')
        response = dict(status='fail', hosts=[])
        report = await self.data_svc.locate('vulnerabilityreports',
                                            match=dict(id=report_id))
        if report:
            report = report[0]
            response['status'] = 'success'
        else:
            return response

        for host in report.hosts.values():
            host_info = dict(name=host.hostname)
            host_info['report_id'] = report.id
            host_info['ip'] = host.ip
            host_info['ports'] = [p for p in host.ports.keys()]
            host_info['os_type'] = host.os.os_type
            host_info['access_prob'] = host.access_prob
            host_info['accessed'] = host._access
            host_info['possible_abilities'] = [a.uuid for a in host.possible_abilities]
            host_info['possible_abilities_success_prob'] = [a.success_prob for a in host.possible_abilities]
            host_info['freebie_abilities'] = host.freebie_abilities
            host_info['denied_abilities'] = host.denied_abilities
            response['hosts'].append(host_info)
        return response

    async def retrieve_edges_from_report(self, data: dict) -> dict:
        """Use id provided by the request, return info on edges in the report.

        Args:
            data: The HTTP request data, assumed to contain an `id` which maps
                  to a vulnerability report in the data service.

        Returns:
            The response status (`'success'` or `'fail'`) as well as a list of
            edges describing the network graph of the matching vulnerability
            report.
        """
        report_id = data.get('report_id')
        response = dict(status='fail', hosts=[])
        report = await self.data_svc.locate('vulnerabilityreports',
                                            match=dict(id=report_id))
        if report:
            report = report[0]
            response['status'] = 'success'
        else:
            return response
        response['edges'] = report.network_map_edges
        return response

    async def update_report_edges(self, data: dict) -> dict:
        """Update a host using the content of the HTTP request body.

        Args:
            data: The HTTP request data, assumed to contain a `host` which has
                  a `report_id` that maps to a vulnerability report in the data
                  service, as well as new entries for the host's name, freebie
                  abilities, possible abilities, or denied abilities.  The host
                  is indexed in its vulnerability report by its ip address.

        Returns:
            The status generated in handling the response, `'fail'` if the
            specified vulnerability report is not found in the data service and
            `'success'` if it is found and the host successfully updated.
        """
        new_edges = data.get('edge_data')
        report_id = data.get('report_id')
        response = dict(status='fail')

        report = await self.data_svc.locate(
                'vulnerabilityreports', match=dict(id=report_id)
            )
        if report:
            report = report[0]
            response['status'] = 'success'
        else:
            return response
        print(f'NEW EDGES: {new_edges}')
        network_map_edges = []
        for edge in new_edges:
            network_map_edges.append((edge[0], edge[1]))
        report.network_map_edges = network_map_edges
        await self.data_svc.remove('vulnerabilityreports',
                                   match=dict(id=report_id))
        await self.data_svc.store(report)
        return response

    async def update_host_in_report(self, data: dict) -> dict:
        """Update a host using the content of the HTTP request body.

        Args:
            data: The HTTP request data, assumed to contain a `host` which has
                  a `report_id` that maps to a vulnerability report in the data
                  service, as well as new entries for the host's name, freebie
                  abilities, possible abilities, or denied abilities.  The host
                  is indexed in its vulnerability report by its ip address.

        Returns:
            The status generated in handling the response, `'fail'` if the
            specified vulnerability report is not found in the data service and
            `'success'` if it is found and the host successfully updated.
        """
        patch_data = data.get('host')
        report_id = patch_data.get('report_id')
        response = dict(status='fail')

        report = await self.data_svc.locate(
                'vulnerabilityreports', match=dict(id=report_id)
            )
        if report:
            report = report[0]
            response['status'] = 'success'
        else:
            return response

        for host_id in report.hosts.keys():
            if host_id == patch_data.get('ip'):
                host = report.hosts[host_id]
                host.name = patch_data.get('name') or host.name
                host.freebie_abilities = patch_data.get('freebie_abilities')
                host.denied_abilities = patch_data.get('denied_abilities')
                new_possible_abilities = zip(
                    patch_data.get('possible_abilities'),
                    patch_data.get('possible_abilities_success_prob')
                )

                new_abilities = []
                for a in new_possible_abilities:
                    new_abilities.append(Ability(uuid=a[0], success_prob=a[1]))

                host.possible_abilities = new_abilities
                report.hosts[host_id] = host
                break

        await self.data_svc.remove('vulnerabilityreports',
                                   match=dict(id=report_id))
        await self.data_svc.store(report)
        return response

    async def get_paths(self, data: dict) -> dict:  # TODO: stub
        """Compute attack paths from a source to a target.

        Args:
            data: The HTTP request data, assumed to contain an `id` which maps
                  to a vulnerability report in the data  service, as well as a
                  target node's ip address and a source node's ip address.

        Returns:
            The path with highest success between the source and target.
        """
        source_ip = data.get('source')
        target_ip = data.get('target')
        report_id = data.get('id')
        response = dict(status='fail', paths=[])

        report = await self.data_svc.locate(
                'vulnerabilityreports', match=dict(id=report_id)
            )
        if report:
            report = report[0]
            response['status'] = 'success'
        else:
            return response
        prob = 0
        for host_id in report.hosts.keys():
            if host_id == target_ip:
                target = report.hosts[host_id]
                possible_abilities = target.possible_abilities
                for ability in possible_abilities:
                    prob = max(prob, float(ability.success_prob))

        test_path = {
            'source': source_ip,
            'target': target_ip,
            'success_prob': prob,
        }
        response['paths'].append(test_path)
        return response

    async def get_paths_v2(self, data: dict) -> dict:
        source_ip = data.get('source')
        target_ip = data.get('target')
        report_id = data.get('id')
        response = dict(status='fail', paths=[], path_success=[], path_stealth=[], path_persistance=[], path_speed=[])

        report = await self.data_svc.locate(
                'vulnerabilityreports', match=dict(id=report_id)
            )
        if report:
            report = report[0]
            response['status'] = 'success'
        else:
            return response
        path_data = await self.pathfinder_svc.get_paths(report=report, initial_host=source_ip, target_host=target_ip)
        paths = path_data.pop('paths')
        sorted_paths = path_data.pop('sorted_paths')

        # highest success prob
        sorted_paths.sort(key=lambda x: sum(float(v[3]) for v in x))
        path_success = copy.deepcopy(sorted_paths)[0]
        print(f'PATH SUCCESS {path_success}')
        # fewest abilities
        sorted_paths.sort(key=lambda x: sum(int(v[4]) for v in x))
        path_stealth = copy.deepcopy(sorted_paths)[0]
        print(f'PATH STELATH {path_stealth}')
        # most hosts
        sorted_paths.sort(key=lambda x: len(x)*(-1))
        path_persistance = copy.deepcopy(sorted_paths)[0]
        print(f'PATH PERSISSTANCE {path_persistance}')
        # fewest edges
        sorted_paths.sort(key=lambda x: len(x))
        path_speed = copy.deepcopy(sorted_paths)[0]
        print(f'PATH SPEED {path_speed}')

        response['paths'] = paths
        response['path_success'] = path_success
        response['path_stealth'] = path_stealth
        response['path_persistance'] = path_persistance
        response['path_speed'] = path_speed
        print(f'RESPONSE: {response}')
        return response

    async def generate_adversary_v2(self, data: dict) -> dict:
        def generate_links(path):
            if path:
                return [
                    dict(source=path[n][0], target=path[n][1], type='path')
                    for n in range(len(path))
                ]
            return []
        print(f'CREATE ADVERASRY REQUEST DATA: {data}')
        path = data.pop('path')
        tags = data.pop('adversary_tags')
        print(f'TYPE TAGS: {type(tags)}')
        if isinstance(tags, str):
            tags = [tags]
        if path:
            path, adv_id = await self.pathfinder_svc.generate_adversary_v2(
                path=path, tags=tags
            )
            print(f'GEN LINKS: {generate_links(path)}')
            return dict(adversary_id=adv_id, new_links=generate_links(path))

    async def check_scan_status(self):
        pending = [s.id for s in self.running_scans.values() if s.status != 'done']
        finished = dict()
        errors = dict()
        for target in [
            t
            for t in self.running_scans.keys()
            if self.running_scans[t].status == 'done'
        ]:
            scan = self.running_scans.pop(target)
            if not scan.returncode:
                source = await self.pathfinder_svc.import_scan(
                    scan.name, os.path.basename(scan.filename)
                )
                finished[scan.id] = dict(source=source.name, source_id=source.id)
            else:
                self.log.debug(scan.output['stderr'])
                errors[scan.id] = dict(message=scan.output['stderr'])
        return dict(pending=pending, finished=finished, errors=errors)

    async def generate_adversary(self, data):
        def generate_links(path):
            if path and len(path) >= 2:
                return [
                    dict(source=path[n], target=path[n + 1], type='path')
                    for n in range(len(path) - 1)
                ]
            return []

        start = data.pop('start')
        target = data.pop('target')
        report_id = data.pop('id')
        report = await self.data_svc.locate(
            'vulnerabilityreports', match=dict(id=report_id)
        )
        tags = data.pop('adversary_tags')
        if report and start and target:
            path, adversary_id = await self.pathfinder_svc.generate_adversary(
                report[0], start, target, tags
            )
            return dict(adversary_id=adversary_id, new_links=generate_links(path))

    async def get_source_name(self, data):
        source = await self.data_svc.locate('sources', dict(id=data['source_id']))
        if source:
            return dict(name=source[0].name)
        return dict()

    @check_authorization
    async def store_report(self, request):
        return await self.file_svc.save_multipart_file_upload(
            request, '%s/reports' % settings.data_dir
        )

    @check_authorization
    async def download_report(self, request):
        report_id = request.query.get('report_id')
        report = await self.data_svc.locate(
            'vulnerabilityreports', match=dict(id=report_id)
        )
        if report:
            try:
                filename = f'{report[0].name}.yml'
                content = yaml.dump(report[0].display).encode('utf-8')
                headers = dict(
                    [
                        ('CONTENT-DISPOSITION', f'attachment; filename={filename}'),
                        ('FILENAME', filename),
                    ]
                )
                return web.Response(body=content, headers=headers)
            except FileNotFoundError:
                return web.HTTPNotFound(body='Report not found')
            except Exception as e:
                return web.HTTPNotFound(body=str(e))

    async def return_scanner_configuration(self, data):
        scanner = data.pop('name')
        if scanner in self.scanners:
            return dict(
                name=scanner,
                fields=[f.__dict__ for f in self.scanners[scanner].fields],
                enabled=self.scanners[scanner].enabled,
                error=False,
            )
        else:
            return dict(name=scanner, error='scanner not able to be found')

    async def load_scanners(self):
        scanners = {}
        for filepath in glob.iglob(
            os.path.join('plugins', 'pathfinder', 'scanners', '*', 'scanner.py')
        ):
            module = import_module(
                filepath.replace('/', '.').replace('\\', '.').replace('.py', '')
            )
            scanner = module.Scanner(dependencies=self.installed_dependencies)
            scanners[scanner.name] = scanner
        return scanners

    async def load_scanner(self, name):
        return import_module('plugins.pathfinder.scanners.%s.scanner' % name)
