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

import pytest

from kube_ncmp import ip_to_prefix
from kube_ncmp import CONFIG
from kube_ncmp import Report
from kube_ncmp import SomeList
from kube_ncmp import SomeListMissuse
from kube_ncmp import Container
from kube_ncmp import NCMashedPotato


def test_ip_to_prefix():
    assert ip_to_prefix("172.25.25.1") == "172.25.x.x"


def test_ip_to_prefix_negative():
    assert ip_to_prefix("172.25.25.1") != "172.25.25.1"


def test_somelist_is_list_enabled():
    class FakeArgs:
        blacklist = ""
        whitelist = ""
    CONFIG.set_args(FakeArgs())

    sl = SomeList()
    scenarious = (
        (False, False, False),
        (True, False, True),
        (False, True, True),
    )
    for sc in scenarious:
        sl.is_blacklist = sc[0]
        sl.is_whitelist = sc[1]
        assert sl.is_list_enabled() == sc[2]


def test_somelist_is_list_enabled_negative():
    class FakeArgs:
        blacklist = ""
        whitelist = ""
    CONFIG.set_args(FakeArgs())

    sl = SomeList()
    scenarious = (
        (False, False, True),
        (True, False, False),
        (False, True, False),
    )
    for sc in scenarious:
        sl.is_blacklist = sc[0]
        sl.is_whitelist = sc[1]
        assert sl.is_list_enabled() != sc[2]


def test_somelist_impossible():
    class FakeArgs:
        blacklist = "/path"
        whitelist = "/path2"
    CONFIG.set_args(FakeArgs())

    with pytest.raises(SomeListMissuse):
        SomeList()


def test_is_container_in_somelist_whitelist(monkeypatch):
    def new_init(self):
        self.is_whitelist = True
        self.is_blacklist = False
        self._somelist = [
            {'host': 1, 'pod': 2, 'container': 3, 'ip': 4},
            {'host': 1},
            {'container': 3},
            {'pod': 2},
            {'ip': 4},
            {'ip': 4, 'pod': 2},
        ]
    monkeypatch.setattr(SomeList, '__init__', new_init)
    containers = [
        (1, 2, 3, 4),
        (1, 0, 0, 0),
        (0, 2, 0, 0),
        (0, 0, 3, 0),
        (0, 0, 0, 4),
        (0, 2, 0, 4),
    ]
    for c in containers:
        cnt = Container(*c)
        sl = SomeList()
        assert sl.is_container_in_somelist(cnt)


def test_is_container_in_somelist_whitelist_negative(monkeypatch):
    def new_init(self):
        self.is_whitelist = True
        self.is_blacklist = False
        self._somelist = [
            {'host': 2, 'pod': 2, 'container': 3, 'ip': 4},
            {'host': 2},
            {'container': 2},
            {'pod': 4},
            {'ip': 3},
            {'ip': 3, 'pod': 2},
        ]
    monkeypatch.setattr(SomeList, '__init__', new_init)
    containers = [
        (1, 2, 3, 4),
        (1, 0, 0, 0),
        (0, 2, 0, 0),
        (0, 0, 3, 0),
        (0, 0, 0, 4),
        (0, 2, 0, 4),
    ]
    for c in containers:
        cnt = Container(*c)
        sl = SomeList()
        assert not sl.is_container_in_somelist(cnt)


def test_is_container_in_somelist_blacklist(monkeypatch):
    def new_init(self):
        self.is_whitelist = False
        self.is_blacklist = True
        self._somelist = [
            {'host': 1, 'pod': 2, 'container': 3, 'ip': 4},
            {'host': 1},
            {'container': 3},
            {'pod': 2},
            {'ip': 4},
            {'ip': 4, 'pod': 2},
        ]
    monkeypatch.setattr(SomeList, '__init__', new_init)
    containers = [
        (1, 2, 3, 4),
        (1, 0, 0, 0),
        (0, 2, 0, 0),
        (0, 0, 3, 0),
        (0, 0, 0, 4),
        (0, 2, 0, 4),
    ]
    for c in containers:
        cnt = Container(*c)
        sl = SomeList()
        assert sl.is_container_in_somelist(cnt)


def test_is_container_in_somelist_blacklist_negative(monkeypatch):
    def new_init(self):
        self.is_whitelist = False
        self.is_blacklist = True
        self._somelist = [
            {'host': 2, 'pod': 2, 'container': 3, 'ip': 4},
            {'host': 2},
            {'container': 2},
            {'pod': 4},
            {'ip': 3},
            {'ip': 3, 'pod': 2},
        ]
    monkeypatch.setattr(SomeList, '__init__', new_init)
    containers = [
        (1, 2, 3, 4),
        (1, 0, 0, 0),
        (0, 2, 0, 0),
        (0, 0, 3, 0),
        (0, 0, 0, 4),
        (0, 2, 0, 4),
    ]
    for c in containers:
        cnt = Container(*c)
        sl = SomeList()
        assert not sl.is_container_in_somelist(cnt)


def test_somelist_is_container_allowed(monkeypatch):
    def new_init(self):
        self.is_whitelist = True
        self.is_blacklist = False
    def new_is_container_in_somelist(self, cnt):
        return True

    monkeypatch.setattr(SomeList, '__init__', new_init)
    monkeypatch.setattr(
        SomeList, 'is_container_in_somelist', new_is_container_in_somelist)
    
    cnt = Container(1, 2, 3, 4)    
    sl = SomeList()
    assert sl.is_container_allowed(cnt)

def test_somelist_is_container_allowed_negative(monkeypatch):
    def new_init(self):
        self.is_whitelist = True
        self.is_blacklist = False
    def new_is_container_in_somelist(self, cnt):
        return False

    monkeypatch.setattr(SomeList, '__init__', new_init)
    monkeypatch.setattr(
        SomeList, 'is_container_in_somelist', new_is_container_in_somelist)
    
    cnt = Container(1, 2, 3, 4)    
    sl = SomeList()
    assert not sl.is_container_allowed(cnt)


def test_container():
    host = "a"
    pod = "b"
    container = "c"
    ip = "d"
    cnt = Container(host, pod, container, ip)
    assert cnt.host == host
    assert cnt.pod == pod
    assert cnt.container == container
    assert cnt.ip == ip


def test_report_ok(monkeypatch, mocker):
    class FakeArgs:
        namespace = ""
    CONFIG.set_args(FakeArgs())

    def new_init(self):
        self.state = mocker.MagicMock()

    monkeypatch.setattr(Report, '__init__', new_init)
    r = Report()
    r.ok(1, 2, 3)
    r.state.labels.assert_called_once()
    r.state.labels().set.assert_called_once()


def test_report_fail(monkeypatch, mocker):
    class FakeArgs:
        namespace = ""
    CONFIG.set_args(FakeArgs())

    def new_init(self):
        self.state = mocker.MagicMock()

    monkeypatch.setattr(Report, '__init__', new_init)

    r = Report()
    r.fail(1, 2, 3)
    r.state.labels.assert_called_once()
    r.state.labels().set.assert_called_once()


def test_ncmp_containers_on_different_nodes(monkeypatch):
    def new_init(self):
        c1 = Container("host0", "pod", "container", "ip")
        c2 = Container("host1", "pod", "container", "ip")
        c3 = Container("host1", "pod", "container", "ip")
        c4 = Container("host2", "pod", "container", "ip")
        c5 = Container("host2", "pod", "container", "ip")
        self._containers = [c1, c2, c3, c4, c5]

    monkeypatch.setattr(NCMashedPotato, '__init__', new_init)
    cnt = Container("host0", "pod", "container", "ip")

    ncmp = NCMashedPotato()
    all_hosts = [i.host for i in
                 ncmp._containers_on_different_nodes(cnt)]
    assert len(all_hosts) == 3


def test_ncmp_check_connection(monkeypatch, mocker):
    def new_init(self):
        self._containers = []

    monkeypatch.setattr(NCMashedPotato, '__init__', new_init)

    c1 = Container("host0", "pod", "container", "ip")
    c2 = Container("host1", "pod", "container", "ip")

    ncmp = NCMashedPotato()

    ncmp.connect_get_namespaced_pod_exec = mocker.MagicMock()
    ncmp._check_connection(c1, c2)

    ncmp.connect_get_namespaced_pod_exec.assert_called_once_with(
        c1, ['/bin/sh', '-c', 'ping -c 2 ip'])


def test_ncmp_validate_connection_between(monkeypatch, mocker):
    def new_init(self):
        self.connectivity_status = {}
        self.report = mocker.MagicMock()

    monkeypatch.setattr(NCMashedPotato, '__init__', new_init)

    c1 = Container("host0", "pod", "container", "ip")
    c2 = Container("host1", "pod", "container", "ip")

    ncmp = NCMashedPotato()

    ncmp._containers = [c1, c2]
    ncmp.connectivity_status = ncmp._generate_report_tempalte()

    ncmp._check_connection = mocker.MagicMock(return_value=ncmp.OK)

    ncmp._validate_connection_between(c1, c2)

    ncmp._check_connection.assert_called_once_with(c1, c2)
    ncmp.report.ok.assert_called_once()
