import argparse
import logging
import json
from pprint import pprint

from kubernetes import client, config
from kubernetes.client import configuration
from kubernetes.stream import stream

from prometheus_client import start_http_server, Summary, Enum


# Configure logging
logger = logging.getLogger('kube-ncmp')
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
logger.addHandler(ch)


# Configure Kubernetes API
config.load_kube_config()
configuration.assert_hostname = False
api_instance = client.CoreV1Api()
ping_pods_cache = "/tmp/%s_ping_pods_cache"


def ip_to_subnet(ip):
    return ".".join(ip.split(".")[:2] + ["x", "x"])


class Report():
    OK = "OK"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"

    def __init__(self, port=8000):
        self.enum_state = Enum(
            'network_state', 'Current state of underlay networking',
            states=[self.UNKNOWN, self.OK, self.FAIL])
        start_http_server(port)

    def report_state(self, report):
        for top_host in report:
            for down_host in report[top_host]:
                for subnet in report[top_host][down_host]:
                    if (
                        report[top_host][down_host][subnet] !=
                        NCMashedPotato.SUCCESS
                    ):
                        self.enum_state.state(self.FAIL)
                        return
        self.enum_state.state(self.OK)


class NCMashedPotato():
    SUCCESS = "Success"

    def __init__(self, namespace, filter, port, use_cache=True):
        self.report = Report(port)

        self.filter = filter or None
        self.namespace = namespace
        self.ping_pods_cache = ping_pods_cache % self.namespace

        self.all_os = self._collect_all_openstack_pods()
        logger.info("Validating nodes %s" % self.all_os)
        self.ping_pods = self._select_only_nodes_with_ping(use_cache=use_cache)

    def _collect_all_openstack_pods(self):
        """
        return: {"hostname": [hostname, pod_name, pod_ip]...}
        """
        os_pods = api_instance.list_namespaced_pod(self.namespace).items

        all_ips = {}

        for pod in os_pods:
            host_name = pod.spec.node_name
            pod_name = pod.metadata.name
            pod_ip = pod.status.pod_ip
            container_name = pod.spec.containers[0].name

            if self.filter and self.filter not in pod_name:
                continue
            if host_name not in all_ips:
                all_ips[host_name] = []
            if pod.status.container_statuses[0].state.running:
                all_ips[host_name].append([host_name, pod_name,
                                           container_name, pod_ip])
        return all_ips

    def _select_only_nodes_with_ping(self, use_cache=False):
        """Go over all pods and collect ones with ping util."""
        logger.info("Collecting pods with ping utility.")

        if use_cache:
            try:
                with open(self.ping_pods_cache, "r") as fl:
                    return json.loads(fl.read())
            except IOError:
                logger.error("No ping_pods cache found")

        ping_pods = {}

        for hostname in self.all_os:
            logger.debug("Checking host %s" % hostname)
            if hostname not in ping_pods:
                ping_pods[hostname] = []
            for pod in self.all_os[hostname]:
                try:
                    resp = stream(
                        api_instance.connect_get_namespaced_pod_exec,
                        pod[1],
                        self.namespace,
                        command=['/bin/sh', '-c', 'ping'],
                        container=pod[2],
                        stderr=True,
                        stdin=False,
                        stdout=True,
                        tty=False
                    )
                    if "not found" not in resp:
                        logger.debug("Ping found at %s" % pod)
                        ping_pods[hostname].append(pod)
                except Exception as err:
                    logger.error(err)
                    raise
        with open(self.ping_pods_cache, "w") as fl:
            fl.write(json.dumps(ping_pods))
        return ping_pods

    def _pods_on_different_nodes(self, pod_ip):
        yielded_hosts = []
        for name in self.all_os:
            for pod in self.all_os[name]:
                if name in yielded_hosts:
                    continue
                if (
                    ".".join(pod_ip.split(".")[:2]) ==
                    ".".join(pod[3].split(".")[:2])
                ):
                    yielded_hosts.append(name)
                    yield pod

    def check_connection(self, name, container, ip):
        """Check connection betwee pod `name` and remote `ip`."""
        exec_command = [
            '/bin/sh',
            '-c',
            'ping -c 2 %s' % ip]
        try:
            resp = stream(
                api_instance.connect_get_namespaced_pod_exec,
                name,
                self.namespace,
                command=exec_command,
                container=container,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False
            )
            logger.debug("Response: " + resp)
            if "0% packet loss" in resp:
                return self.SUCCESS
        except Exception as err:
            logger.error(err)

        # Report Fail before end of validation since we already knwo the result
        self.report.enum_state.state(self.report.FAIL)
        return "Fail"

    def _generate_report_tempalte(self):
        hosts = self.all_os.keys()
        connectivity_status = {}
        for host in hosts:
            connectivity_status[host] = {h: {} for h in hosts}
        return connectivity_status

    def _validate(self):
        self.connectivity_status = self._generate_report_tempalte()

        for ping_host in self.ping_pods:
            for ping_pod in self.ping_pods[ping_host]:
                for remote_pod in self._pods_on_different_nodes(ping_pod[3]):
                    logger.debug(
                        "Check connectivity between differen nodes: "
                        "%s -> %s" % (ping_pod, remote_pod))

                    sub = ip_to_subnet(ping_pod[3])
                    if (
                        sub not in
                        self.connectivity_status[ping_host][remote_pod[0]]
                    ):
                        self.connectivity_status[
                            ping_host][remote_pod[0]][sub] = {}

                    # We already had one successful attempt, underlay network
                    # is working
                    if (
                        self.connectivity_status[ping_host][remote_pod[0]][
                            sub] == self.SUCCESS
                    ):
                        continue
                    else:
                        st = self.check_connection(ping_pod[1], ping_pod[2],
                                                   remote_pod[3])
                        self.connectivity_status[
                            ping_host][remote_pod[0]][sub] = st

                    print("Current state:")
                    pprint(self.connectivity_status)

        print("~" * 80)
        print("Final state:")
        print("~" * 80)
        pprint(self.connectivity_status)

        return self.connectivity_status

    def start_validation(self):
        logger.info("Start infinity loop.")
        while True:
            logger.debug("Start validation.")
            result = self._validate()
            logger.debug("Validation complete. Report state to Prometeus.")
            self.report.report_state(result)


def main():
    parser = argparse.ArgumentParser(
        prog='NC Mashed Potato',
        description='Tool to validate interconnection between containers '
                    'in kubernetes cloud.')
    parser.add_argument('--cache', action='store_true',
                        help='Use cached collection of nodes with ping.')
    parser.add_argument('--namespace', default='openstack',
                        help='Kuberenetes namespace to play with.')
    parser.add_argument('--filter', default='',
                        help='Pod should have it in name.')
    parser.add_argument('--port', type=int, default=8000,
                        help='Port for Prometeus.')

    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    if args.debug:
        ch.setLevel(logging.DEBUG)

    NCMashedPotato(namespace=args.namespace,
                   filter=args.filter,
                   port=args.port,
                   use_cache=args.cache).start_validation()


if __name__ == "__main__":
    main()
