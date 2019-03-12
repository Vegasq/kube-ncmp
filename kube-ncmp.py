#!/usr/bin/python3
# Copyright 2019 AT&T Intellectual Property. All other rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import logging
import json
import time
from pprint import pprint

from kubernetes import client, config
from kubernetes.config import config_exception
from kubernetes.client import configuration
from kubernetes.stream import stream

from prometheus_client import start_http_server, Gauge
from prometheus_client.core import REGISTRY
from prometheus_client.process_collector import PROCESS_COLLECTOR
from prometheus_client.platform_collector import PLATFORM_COLLECTOR


# Configure logging
logger = logging.getLogger("kube-ncmp")
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)


def ip_to_prefix(ip):
    return ".".join(ip.split(".")[:2] + ["x", "x"])


class Config:
    def set_args(self, args):
        self._args = args

    @property
    def namespace(self):
        return self._args.namespace

    @property
    def filter(self):
        return self._args.filter

    @property
    def port(self):
        return self._args.port

    @property
    def use_cache(self):
        return self._args.cache

    @property
    def sleep(self):
        return self._args.sleep

    @property
    def show_system_info(self):
        return self._args.show_system_info


CONFIG = Config()


class Container:
    def __init__(self, host, pod, container, ip):
        self.host = host
        self.pod = pod
        self.container = container
        self.ip = ip

    def __str__(self):
        return "[{host}/{pod}/{container}/{ip}]".format(
            host=self.host, pod=self.pod, container=self.container, ip=self.ip)


class Report:
    OK = 0
    FAIL = 1

    def __init__(self):
        self.state = Gauge(
            "network_state",
            "Current state of underlay networking",
            labelnames=['host_from', 'host_to', 'namespace', 'network']
        )
        if not CONFIG.show_system_info:
            REGISTRY.unregister(PROCESS_COLLECTOR)
            REGISTRY.unregister(PLATFORM_COLLECTOR)

        start_http_server(CONFIG.port)

    def ok(self, host_from, host_to, network):
        self.state.labels(
            host_from=host_from,
            host_to=host_to,
            namespace=CONFIG.namespace,
            network=network).set(self.OK)

    def fail(self, host_from, host_to, network):
        self.state.labels(
            host_from=host_from,
            host_to=host_to,
            namespace=CONFIG.namespace,
            network=network).set(self.FAIL)


class Cache:
    ping_pods_cache_path = "/var/log/%s_ping_pods_cache"

    @classmethod
    def load(cls):
        cls.ping_pods_cache = cls.ping_pods_cache_path % CONFIG.namespace

        try:
            with open(cls.ping_pods_cache, "r") as fl:
                data = json.loads(fl.read())
                return [Container(*d) for d in data]
        except IOError:
            logger.error("No ping_pods cache found")
        return None

    @classmethod
    def save(cls, pods):
        cls.ping_pods_cache = cls.ping_pods_cache_path % CONFIG.namespace
        dump_me = [(p.host, p.pod, p.container, p.ip) for p in pods]
        with open(cls.ping_pods_cache, "w") as fl:
            fl.write(json.dumps(dump_me))


class NCMashedPotato:
    OK = "Success"
    FAIL = "Fail"

    def __init__(self):
        conf = client.Configuration()
        conf.verify_ssl = False

        try:
            config.load_incluster_config()
        except config_exception.ConfigException:
            # Fallback for non-container usage
            config.load_kube_config()

        configuration.assert_hostname = False
        self.api = client.CoreV1Api()

        # To communicate with Prometeus
        self.report = Report()
        self._containers = self._collect_all_containers()
        self._ping_containers = self._collect_containers_with_ping()

    def _collect_all_containers(self):
        os_pods = self.api.list_namespaced_pod(CONFIG.namespace).items
        if CONFIG.filter:
            os_pods = [p for p in os_pods if CONFIG.filter in p.metadata.name]

        containers = []

        for pod in os_pods:
            host_name = pod.spec.node_name
            # TODO(vegasq): We select only first container within pod,
            #               should we use all of them?
            container_name = pod.spec.containers[0].name

            if pod.status.container_statuses[0].state.running:
                cnt = Container(
                    host=host_name, pod=pod.metadata.name,
                    container=container_name, ip=pod.status.pod_ip)
                containers.append(cnt)

        return containers

    def _collect_containers_with_ping(self):
        """Go over all containers and collect ones with ping util."""
        logger.debug("Collecting pods with ping utility.")

        if CONFIG.use_cache:
            pods = Cache.load()
            if pods:
                return pods

        ping_pods = []

        for container in self._containers:
            try:
                resp = self.connect_get_namespaced_pod_exec(
                    container, ["/bin/sh", "-c", "ping"])
                if "Usage: ping" in resp:
                    logger.debug("Ping found at %s" % container)
                    ping_pods.append(container)
            except Exception as err:
                logger.error(err)

        Cache.save(ping_pods)
        return ping_pods

    def connect_get_namespaced_pod_exec(self, container, cmd):
        return stream(
            self.api.connect_get_namespaced_pod_exec,
            container.pod,
            CONFIG.namespace,
            command=cmd,
            container=container.container,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )

    def _containers_on_different_nodes(self, container):
        """Look for a containers in same networks on a variety of hosts."""
        yielded_hosts = []
        for remote_container in self._containers:
            if remote_container.host in yielded_hosts:
                continue
            if ip_to_prefix(container.ip) == ip_to_prefix(remote_container.ip):
                # We need ony one pod per node, so we track already found
                # nodes.
                yielded_hosts.append(remote_container.host)
                yield remote_container

    def _check_connection(self, cnt_a, cnt_b):
        """Use K8S API method connect_get_namespaced_pod_exec to ping
        specifyed IP.
        """
        exec_command = ["/bin/sh", "-c", "ping -c 2 %s" % cnt_b.ip]

        try:
            resp = self.connect_get_namespaced_pod_exec(cnt_a, exec_command)

            logger.debug("Response: " + resp)
            if "0% packet loss" in resp:
                return self.OK
        except Exception as err:
            logger.error(err)

        return self.FAIL

    def _generate_report_tempalte(self):
        """For every loop cycle, create new dict of hosts."""
        hosts = set([cnt.host for cnt in self._containers])
        connectivity_status = {}
        for host in hosts:
            connectivity_status[host] = {h: {} for h in hosts}
        return connectivity_status

    def _validate_connection_between(self, cnt_a, cnt_b):
        """Check connectivity between two nodes if state between nodes
        is unknown, and report status.
        """
        sub = ip_to_prefix(cnt_a.ip)
        if sub not in self.connectivity_status[cnt_a.host][cnt_b.host]:
            self.connectivity_status[cnt_a.host][cnt_b.host][sub] = None

        # We already had one successful attempt, underlay network is working
        if self.connectivity_status[cnt_a.host][cnt_b.host][sub] == self.OK:
            return
        else:
            st = self._check_connection(cnt_a, cnt_b)
            print("Connection between %s and %s via %s is %s."
                  % (cnt_a, cnt_b, sub, st))

            # Report state to Prometheus
            f = self.report.ok if st == self.OK else self.report.fail
            f(host_from=cnt_a.host, host_to=cnt_b.host, network=sub)

            # Keep result to not report multiple times.
            self.connectivity_status[cnt_a.host][cnt_b.host][sub] = st

    def _validate(self):
        """Start validation cycle."""
        self.connectivity_status = self._generate_report_tempalte()

        for cnt in self._ping_containers:
            for remote_cnt in self._containers_on_different_nodes(cnt):
                logger.debug(
                    "Check connectivity between differen nodes: "
                    "%s -> %s" % (cnt, remote_cnt))
                self._validate_connection_between(cnt, remote_cnt)

        pprint(self.connectivity_status)

    def start_validation(self):
        logger.debug("Start infinity loop.")
        while True:
            logger.debug("Start validation.")
            self._validate()
            time.sleep(CONFIG.sleep)


def parse_args_to_config():
    parser = argparse.ArgumentParser(
        prog="NC Mashed Potato",
        description="Tool to validate interconnection between containers "
        "in kubernetes cloud.",
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Use cached collection of nodes with ping.",
    )
    parser.add_argument(
        "--namespace",
        default="openstack",
        help="Kuberenetes namespace to play with.",
    )
    parser.add_argument(
        "--filter", default="", help="Pod should have it in name."
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port for Prometeus."
    )
    parser.add_argument(
        "--sleep", type=int, default=0, help="How long to sleep between runs."
    )
    parser.add_argument(
        "--show-system-info",
        action="store_true",
        help="Enable process and platform collectors."
    )
    CONFIG.set_args(parser.parse_args())


def main():
    parse_args_to_config()
    NCMashedPotato().start_validation()


if __name__ == "__main__":
    main()
