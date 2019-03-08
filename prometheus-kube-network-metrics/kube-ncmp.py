#!/usr/bin/python
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
import subprocess
from pprint import pprint

from kubernetes import client, config
from kubernetes.client import configuration
from kubernetes.stream import stream

from prometheus_client import start_http_server, Enum


# Configure logging
logger = logging.getLogger("kube-ncmp")
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)


def ip_to_subnet(ip):
    return ".".join(ip.split(".")[:2] + ["x", "x"])


class Report:
    OK = "OK"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"

    def __init__(self, port=8000):
        self.enum_state = Enum(
            "network_state",
            "Current state of underlay networking",
            states=[self.UNKNOWN, self.OK, self.FAIL],
        )
        start_http_server(port)

    def report_state(self, report):
        for top_host in report:
            for down_host in report[top_host]:
                for subnet in report[top_host][down_host]:
                    if (
                        report[top_host][down_host][subnet]
                        != NCMashedPotato.SUCCESS
                    ):
                        # It's already reported as fail, so probaly we can
                        # skip self.fail() call.
                        self.fail()
                        return
        self.ok()

    def ok(self):
        self.enum_state.state(self.OK)

    def fail(self):
        self.enum_state.state(self.FAIL)


class Cache:
    ping_pods_cache_path = "/var/log/%s_ping_pods_cache"

    @classmethod
    def load(cls, namespace):
        cls.ping_pods_cache = cls.ping_pods_cache_path % namespace

        try:
            with open(cls.ping_pods_cache, "r") as fl:
                return json.loads(fl.read())
        except IOError:
            logger.error("No ping_pods cache found")
        return None

    @classmethod
    def save(cls, namespace, pods):
        cls.ping_pods_cache = cls.ping_pods_cache_path % namespace
        with open(cls.ping_pods_cache, "w") as fl:
            fl.write(json.dumps(pods))


class NCMashedPotato:
    SUCCESS = "Success"
    FAIL = "Fail"

    def __init__(self, namespace, filter, port, use_cache=True):
        self.filter = filter or None
        self.namespace = namespace
        self.kube_api_client = self.get_api()
        self.api = client.CoreV1Api(self.kube_api_client)

        # To communicate with Prometeus
        self.report = Report(port)
        self.pods_in_nodes = self._collect_all_namespaced_pods()
        self.ping_pods = self._select_only_nodes_with_ping(use_cache=use_cache)


    def get_api(self):
        cmd = ("kubectl describe secret $(kubectl get secrets |" "grep ^prometheus-kube-network-metrics | cut -f1 -d ' ') | grep -E '^token'" "|cut -f2 -d':'|tr -d ' '")
        token = subprocess.check_output(cmd, stderr=subprocess.STDOUT,shell=True).decode('utf-8').strip("\n")
        conf = client.Configuration()
        conf.api_key = {"authorization": "Bearer " + token}
        conf.verify_ssl = False
        conf.host="https://10.96.0.1:443"
        api_client = client.ApiClient(conf)
        return api_client
         

    def _collect_all_namespaced_pods(self):
        """
        return: {"hostname": [hostname, pod_name, pod_ip]...}
        """
        os_pods = self.api.list_namespaced_pod(self.namespace).items
        if self.filter:
            os_pods = [p for p in os_pods if self.filter in p.metadata.name]
        pods_in_nodes = {}

        for pod in os_pods:
            host_name = pod.spec.node_name
            # TODO(Mykola): We select only first container within pod,
            #               should we use all of them?
            container_name = pod.spec.containers[0].name

            if host_name not in pods_in_nodes:
                pods_in_nodes[host_name] = []

            if pod.status.container_statuses[0].state.running:
                pods_in_nodes[host_name].append(
                    [
                        host_name,
                        pod.metadata.name,
                        container_name,
                        pod.status.pod_ip,
                    ]
                )

        return pods_in_nodes

    def _select_only_nodes_with_ping(self, use_cache=False):
        """Go over all pods and collect ones with ping util."""
        logger.debug("Collecting pods with ping utility.")

        if use_cache:
            pods = Cache.load(self.namespace)
            if pods:
                return pods

        ping_pods = {}

        for hostname in self.pods_in_nodes:
            if hostname not in ping_pods:
                ping_pods[hostname] = []

            for pod in self.pods_in_nodes[hostname]:
                try:
                    resp = self.connect_get_namespaced_pod_exec(
                        pod[1], pod[2], ["/bin/sh", "-c", "ping"]
                    )
                    if "not found" not in resp:
                        logger.debug("Ping found at %s" % pod)
                        ping_pods[hostname].append(pod)
                except Exception as err:
                    logger.error(err)

        # We will save it even when use_cache == False, so we can use it next
        # if we want to.
        Cache.save(self.namespace, ping_pods)
        return ping_pods

    def connect_get_namespaced_pod_exec(self, pod_name, container_name, cmd):
        return stream(
            self.api.connect_get_namespaced_pod_exec,
            pod_name,
            self.namespace,
            command=cmd,
            container=container_name,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )

    def _pods_on_different_nodes(self, pod_ip):
        """Look for a single pod per node that have same subnet."""
        yielded_hosts = []
        for name in self.pods_in_nodes:
            for pod in self.pods_in_nodes[name]:
                if name in yielded_hosts:
                    continue
                if ip_to_subnet(pod_ip) == ip_to_subnet(pod[3]):
                    # We need ony one pod per node, so we track already found
                    # nodes.
                    yielded_hosts.append(name)
                    yield pod

    def check_connection(self, name, container, ip):
        """Use K8S API method connect_get_namespaced_pod_exec to ping
        specifyed IP.

        Only output with `0% packet loss` in it recognized as successful.
        """
        exec_command = ["/bin/sh", "-c", "ping -c 2 %s" % ip]
        try:
            resp = self.connect_get_namespaced_pod_exec(
                name, container, exec_command
            )

            logger.debug("Response: " + resp)
            if "0% packet loss" in resp:
                return self.SUCCESS
        except Exception as err:
            logger.error(err)

        # Report Fail before end of validation since we already knwo the result
        return self.FAIL

    def _generate_report_tempalte(self):
        """For every loop cycle, create new dict of hosts."""
        hosts = self.pods_in_nodes.keys()
        connectivity_status = {}
        for host in hosts:
            connectivity_status[host] = {h: {} for h in hosts}
        return connectivity_status

    def _validate_connection_between(self, pod_a, pod_b):
        """Check connectivity between two nodes if state between nodes
        is unknown, and update connection status report.

        If connectivity is broken, report failure immediately.
        """
        sub = ip_to_subnet(pod_a[3])
        if sub not in self.connectivity_status[pod_a[0]][pod_b[0]]:
            self.connectivity_status[pod_a[0]][pod_b[0]][sub] = {}

        # We already had one successful attempt, underlay network
        # is working
        if self.connectivity_status[pod_a[0]][pod_b[0]][sub] == self.SUCCESS:
            return
        else:
            st = self.check_connection(pod_a[1], pod_a[2], pod_b[3])
            print(
                "Connection between %s and %s via %s is %s."
                % (pod_a, pod_b, sub, st)
            )

            if st == self.FAIL:
                self.report.fail()
            self.connectivity_status[pod_a[0]][pod_b[0]][sub] = st

    def _validate(self):
        """Start validation cycle."""
        self.connectivity_status = self._generate_report_tempalte()

        for ping_host in self.ping_pods:
            for ping_pod in self.ping_pods[ping_host]:
                for remote_pod in self._pods_on_different_nodes(ping_pod[3]):
                    logger.debug(
                        "Check connectivity between differen nodes: "
                        "%s -> %s" % (ping_pod, remote_pod)
                    )
                    # It will update self.connectivity_status
                    self._validate_connection_between(ping_pod, remote_pod)

        # TODO(Mykola): is self.DEBUG ?
        pprint(self.connectivity_status)

        return self.connectivity_status

    def start_validation(self):
        """Infinite loop"""
        logger.debug("Start infinity loop.")
        while True:
            logger.debug("Start validation.")
            result = self._validate()
            logger.debug("Validation complete. Report state to Prometeus.")
            self.report.report_state(result)


def main():
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
    args = parser.parse_args()

    NCMashedPotato(
        namespace=args.namespace,
        filter=args.filter,
        port=args.port,
        use_cache=args.cache,
    ).start_validation()


if __name__ == "__main__":
    main()
