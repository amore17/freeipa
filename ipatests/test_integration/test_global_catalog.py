#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import re
from contextlib import contextmanager
from io import StringIO
import time
import textwrap
import pytest
import json
import winrm
import string
import random

from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration import windows_tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.util import skipl_context, wait_for

from ldif import LDIFRecordList

gc_dirsrv_service = 'dirsrv@GLOBAL-CATALOG.service'
gcsyncd_service = 'ipa-gcsyncd.service'
LOG_MESSAGE_GC_INITIALIZED = \
    'Initial LDAP dump is done, now synchronizing with GC'

def is_service_active(host, service):
    res = host.run_command(['systemctl', 'is-active', service],
                           ok_returncode=[0,3])
    return res.returncode == 0


def ldapsearch_gc(client_host, server_hostname, scope='base', base=None,
                  search_filter='(objectclass=*)', properties=None):
    if isinstance(properties, str):
        properties = properties.split()
    args = [
        'ldapsearch',
        '-ZZ',
        '-LLL',
        '-h', server_hostname,
        '-p', '3268',
        '-s', scope,
        '-o', 'ldif-wrap=no']
    if base:
        args.extend(['-b', base])
    args.append(search_filter)
    args.extend(properties or [])
    res = client_host.run_command(args, ok_returncode=[0, 32])
    if res.returncode == 32:
        return []
    records = LDIFRecordList(StringIO(res.stdout_text))
    records.parse()
    return records.all_records


def disable_network_manager_resolv_conf_management(host):
    content = textwrap.dedent('''
        [main]
        dns=none
    ''')
    host.put_file_contents('/etc/NetworkManager/conf.d/ipatests.conf', content)
    host.run_command(['systemctl', 'restart', 'NetworkManager.service'])


def get_windows_logged_on_user(host):
    res = windows_tasks.winrm_run_powershell_script(
        host,
        'Get-WMIObject -class Win32_ComputerSystem -ComputerName 127.0.0.1'
        '| ConvertTo-Json')
    return json.loads(res.stdout_text)['UserName']


@contextmanager
def log_tail(host, log_file):
    size = 0
    if host.transport.file_exists(log_file):
        size = int(
            host.run_command(['stat', '--format', '%s', log_file]).stdout_text)

    def tail():
        return host.get_file_contents(log_file)[size:].decode('utf-8')

    yield tail


def decode_ad_group_type(s):
    # source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/11972272-09ec-4a42-bf5e-3e99b321cf55
    types = {
        0x00000001: 'BUILTIN_LOCAL_GROUP',
        0x00000002: 'ACCOUNT_GROUP',
        0x00000004: 'RESOURCE_GROUP',
        0x00000008: 'UNIVERSAL_GROUP',
        0x00000010: 'APP_BASIC_GROUP',
        0x00000020: 'APP_QUERY_GROUP',
        0x80000000: 'SECURITY_ENABLED'
    }
    bit_mask = int(s)
    if bit_mask < 0:
        bit_mask += (1 << 32)
    group_type = set()
    for i in range(32):
        type_value = (1 << i)
        if (bit_mask & type_value):
            group_type.add(types[type_value])
    return group_type


def setup_debug_log_for_global_gatalog(host):
    contents = textwrap.dedent('''
        [global]
        debug=True
    ''')
    host.put_file_contents('/etc/ipa/globalcatalog.conf', contents)


def get_changes_in_gc_log(s):
    changes_lines = []
    for line in s.splitlines():
        if re.search(r'\b(user|group)_(add|del)\b', line):
            changes_lines.append(line)
    return changes_lines


class SimpleTestUser:
    def __init__(self, first, last):
        self.first = first
        self.last = last

    @property
    def login(self):
        return self.first + self.last

    @property
    def cn(self):
        return '{} {}'.format(self.first, self.last)

    @property
    def password(self):
        return 'Secret{}{}1'.format(self.first, self.last)


parametrize_login_formats = pytest.mark.parametrize(
    ['login_format', 'user_case', 'domain_case','domain_abbreviated'], [

    pytest.param('upn', 'lower', 'lower', False, id='user@ipa.test'),
    pytest.param('upn', 'lower', 'upper', False, id='user@IPA.TEST'),
    pytest.param('upn', 'lower', 'mixed', False, id='user@Ipa.Test'),

    pytest.param('upn', 'lower', 'lower', True, id='user@ipa',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
    pytest.param('upn', 'lower', 'upper', True, id='user@IPA',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
    pytest.param('upn', 'lower', 'mixed', True, id='user@Ipa',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),

    pytest.param('down-level', 'lower', 'lower', False, id='ipa.test\\user',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
    pytest.param('down-level', 'lower', 'upper', False, id='IPA.TEST\\user'),
    pytest.param('down-level', 'lower', 'mixed', False, id='Ipa.Test\\user',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),

    pytest.param('down-level', 'lower', 'lower', True, id='ipa\\user',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
    pytest.param('down-level', 'lower', 'upper', True, id='IPA\\user',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
    pytest.param('down-level', 'lower', 'mixed', True, id='Ipa\\user',
                 marks=pytest.mark.skipl(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),

    pytest.param('upn', 'upper', 'lower', False, id='USER@ipa.test'),
    pytest.param('upn', 'mixed', 'lower', False, id='User@ipa.test'),

    pytest.param('down-level', 'upper', 'upper', False, id='IPA.TEST\\USER'),
    pytest.param('down-level', 'mixed', 'upper', False, id='IPA.TEST\\User'),
])


class TestGlobalCatalogInstallation(IntegrationTest):
    topology = 'star'
    num_clients = 1
    num_replicas = 1
    num_ad_domains = 1
    num_ad_root_clients = 1

    @classmethod
    def install(cls, mh):
        super().install(mh)

        cls.ad_controller = cls.ads[0]
        cls.ad_client = cls.ad_domains[0].clients[0]
        cls.client = cls.clients[0]
        cls.replica = cls.replicas[0]

        # FIXME: this should be done in PR-CI:
        # https://github.com/freeipa/freeipa-pr-ci/pull/373
        tasks.config_host_resolvconf_with_master_data(cls.master, cls.client)
        disable_network_manager_resolv_conf_management(cls.client)
        tasks.config_host_resolvconf_with_master_data(cls.master, cls.replica)
        disable_network_manager_resolv_conf_management(cls.replica)

        setup_debug_log_for_global_gatalog(cls.master)
        for host in [cls.master, cls.client]:
            host.run_command(['dnf', 'install', '-y', 'python3-winrm',
                                    'python3-requests-kerberos'])

    @property
    def main_dirsrv_service(self):
        return 'dirsrv@{}.service'.format(
            self.master.domain.realm.replace('.', '-'))

    def get_gc_record(self, user_or_group):
        tasks.kinit_admin(self.master)
        result = ldapsearch_gc(
            self.master, self.master.hostname,
            base='cn={},cn=users,{}'.format(
                user_or_group, self.master.domain.basedn))
        assert len(result) <= 1
        return result[0] if result else None

    def make_dn(self, user_or_group):
        return 'cn={},cn=users,{}'.format(
            user_or_group, self.master.domain.basedn)

    def assert_is_member_of_groups(self, user_or_group, expected_groups):
        record = self.get_gc_record(user_or_group)
        assert record is not None
        member_of = [g.decode('utf-8')
                     for g in record[1].get('memberOf', [])]
        expected_member_of = [self.make_dn(group) for group in expected_groups]
        assert set(expected_member_of) == set(member_of)

    def assert_group_members_equal(self, group, expected_members):
        record = self.get_gc_record(group)
        assert record is not None
        members = [m.decode('utf-8')
                   for m in record[1].get('member', [])]
        expected_members = [self.make_dn(m) for m in expected_members]
        assert set(expected_members) == set(members)

    def assert_does_not_exist_in_gc(self, user_or_group):
        assert self.get_gc_record(user_or_group) is None

    def assert_exists_in_gc(self, user_or_group):
        record = self.get_gc_record(user_or_group)
        assert record is not None
        assert record[0] == self.make_dn(user_or_group)

    def validate_and_parse_gcsync_cookie(self):
        cookie_str = self.master.get_file_contents(paths.GC_COOKIE, 'utf-8').strip()
        fields = cookie_str.split('#')
        assert fields[0] == '{}:389'.format(self.master.hostname)
        assert fields[1] == 'cn=Directory Manager:cn=accounts,{}:(|(objectClass=groupofnames)(objectClass=person))'.format(self.master.domain.basedn)
        sn = int(fields[2])
        assert sn < 1000000
        return sn

    initial_test_data = {
        'user1': SimpleTestUser('First', 'InitialUser'),
        'user2': SimpleTestUser('Second', 'InitialUser'),
        'group1': 'initialgroup1',
        'group2': 'initialgroup2',
        'group3': 'initialgroup3'
    }

    def test_initial_data_imported_setup(self):
        user1 = self.initial_test_data['user1']
        user2 = self.initial_test_data['user2']
        group1 = self.initial_test_data['group1']
        group2 = self.initial_test_data['group2']
        group3 = self.initial_test_data['group3']

        tasks.user_add(self.master, user1.login, user1.first, user1.last)
        tasks.user_add(self.master, user2.login, user2.first, user2.last)
        tasks.group_add(self.master, group1)
        tasks.group_add(self.master, group2)
        tasks.group_add(self.master, group3)
        self.master.run_command(['ipa', 'group-add-member', group1,
                                 '--users', user1.login])
        self.master.run_command(['ipa', 'group-add-member', group2,
                                 '--users', user1.login])
        self.master.run_command(['ipa', 'group-add-member', group2,
                                 '--groups', group1])

    def test_adtrust_install(self):
        Firewall(self.master).enable_service("freeipa-trust")
        assert not is_service_active(self.master, gc_dirsrv_service)
        assert not is_service_active(self.master, gcsyncd_service)
        self.master.run_command(['systemctl', 'is-active', gcsyncd_service],
                                ok_returncode=3)

        with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
            res = self.master.run_command(['ipa-adtrust-install', '-U', '-a',
                                           self.master.config.admin_password,
                                           '--add-sids'])
            assert re.search('ports are open.+TCP Ports.+3268: msft-gc.+UDP Ports',
                            res.stdout_text, re.DOTALL)
            assert is_service_active(self.master, gc_dirsrv_service)
            assert is_service_active(self.master, gcsyncd_service)

            assert wait_for(
                lambda: LOG_MESSAGE_GC_INITIALIZED  in get_log_tail(), 30)

            log = get_log_tail()
            assert log.count(LOG_MESSAGE_GC_INITIALIZED ) == 1
            assert 'ERROR' not in log

    def test_initial_data_imported(self):
        user1 = self.initial_test_data['user1']
        user2 = self.initial_test_data['user2']
        group1 = self.initial_test_data['group1']
        group2 = self.initial_test_data['group2']
        group3 = self.initial_test_data['group3']

        self.assert_is_member_of_groups(user1.cn, ['ipausers', group1, group2])
        self.assert_is_member_of_groups(user2.cn, ['ipausers'])
        self.assert_is_member_of_groups(group1, [group2])
        self.assert_group_members_equal(group1, [user1.cn])
        self.assert_is_member_of_groups(group2, [])
        self.assert_group_members_equal(group2, [user1.cn, group1])
        self.assert_is_member_of_groups(group3, [])
        self.assert_group_members_equal(group3, [])

    def test_initial_data_imported_cleanup(self):
        tasks.user_del(self.master, self.initial_test_data['user1'].login)
        tasks.user_del(self.master, self.initial_test_data['user2'].login)
        tasks.group_del(self.master, self.initial_test_data['group1'])
        tasks.group_del(self.master, self.initial_test_data['group2'])
        tasks.group_del(self.master, self.initial_test_data['group3'])

    def test_gc_dns_records(self):
        expected = '0 100 3268 {}.'.format(self.master.hostname)
        gc_records = [
            '_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs',
            '_ldap._tcp.gc._msdcs',
            '_gc._tcp.Default-First-Site-Name._sites',
            '_gc._tcp',
        ]
        for record in gc_records:
            res = self.master.run_command([
                'dig', '{}.{}'.format(record, self.master.domain.name),
                '+short', 'SRV'])
            assert expected == res.stdout_text.strip()

    def test_establish_trust_with_ad(self):
        tasks.configure_dns_for_trust(self.master, self.ad_controller)
        tasks.configure_windows_dns_for_trust(self.ad_controller, self.master)
        tasks.establish_trust_with_ad(
            self.master, self.ad_controller.domain.name,
            extra_args=['--two-way=True'])
        tasks.configure_ipa_client_for_ad_trust(self.client)
        win_admin = '{}@{}'.format(self.ad_controller.ssh_username,
                                   self.ad_controller.domain.realm)
        self.master.run_command(['ipa', 'idoverrideuser-add',
                                 'Default Trust View', win_admin])

    @pytest.fixture(scope='function')
    def access_test_users(self):
        ipa_user = SimpleTestUser('Access', 'Test')
        tasks.create_active_user(
            self.master, ipa_user.login, ipa_user.password,
            ipa_user.first, ipa_user.last)
        yield {
            'ipa': {
                'login': ipa_user.login,
                'password': ipa_user.password,
            },
            'ipa_admin': {
                'login': 'admin',
                'password': self.master.config.admin_password
            },
            'ad': {
                'login': 'testuser@' + self.ad_controller.domain.name,
                'password': 'Secret123'
            }
        }
        tasks.user_del(self.master, ipa_user.login)

    @pytest.mark.parametrize('host', ['master', 'client', 'replica'])
    @pytest.mark.parametrize('user_type', ['ipa', 'ipa_admin', 'ad'])
    def test_users_can_read_global_catalog(self, access_test_users,
                                           host, user_type):
        host = getattr(self, host)
        user = access_test_users[user_type]
        tasks.kinit_as_user(host, user['login'], user['password'])
        res = ldapsearch_gc(host, self.master.hostname,
                            base=self.make_dn('Administrator'))
        assert len(res) == 1
        assert res[0][0] == self.make_dn('Administrator')

    @pytest.mark.parametrize('user_type', ['ipa', 'ipa_admin', 'ad'])
    def test_users_can_not_modify_global_catalog(self,
                                                 access_test_users, user_type):
        user = access_test_users[user_type]
        tasks.kinit_as_user(self.master, user['login'], user['password'])
        ldiff_add = textwrap.dedent('''
            dn: {dn}
            changetype: add
            objectClass: top
        ''').format(dn=self.make_dn('Unexpected User'))
        ldiff_modify = textwrap.dedent('''
            dn: {dn}
            changetype: modify
            replace: givenName
            givenName: Unexpected
        ''').format(dn=self.make_dn('Administrator'))
        ldiff_remove = textwrap.dedent('''
            dn: {dn}
            changetype: delete
        ''').format(dn=self.make_dn('Administrator'))
        for ldiff in [ldiff_add, ldiff_modify, ldiff_remove]:
            res = self.master.run_command(
                ['ldapmodify', '-h', self.master.hostname, '-p', '3268'],
                stdin_text=ldiff, ok_returncode=50)
            assert 'Insufficient access' in res.stderr_text

    def test_can_not_read_global_catalog_without_kerberos_ticket(self):
        tasks.kdestroy_all(self.master)
        self.master.run_command(
            ['ldapsearch', '-h', self.master.hostname, '-p', '3268'],
            ok_returncode=254)
        self.master.run_command(
            ['ldapmodify', '-h', self.master.hostname, '-p', '3268'],
            ok_returncode=254)

    def test_membership_synchronization(self):
        user1 = SimpleTestUser('First', 'Syncuser')
        group1 = 'syncgroup1'
        group2 = 'syncgroup2'
        group3 = 'syncgroup3'

        try:
            # check preconditions
            self.assert_does_not_exist_in_gc(user1.cn)
            self.assert_does_not_exist_in_gc(group1)
            self.assert_does_not_exist_in_gc(group2)
            self.assert_does_not_exist_in_gc(group3)

            # user is created
            tasks.user_add(self.master, user1.login, user1.first, user1.last)
            self.assert_is_member_of_groups(user1.cn, ['ipausers'])

            # group is created
            tasks.group_add(self.master, group1)
            self.assert_is_member_of_groups(group1, [])
            self.assert_group_members_equal(group1, [])

            # user added to group
            self.master.run_command(['ipa', 'group-add-member', group1, '--users', user1.login])
            self.assert_is_member_of_groups(user1.cn, ['ipausers', group1])
            self.assert_group_members_equal(group1, [user1.cn])

            # group added to another group
            tasks.group_add(self.master, group2)
            self.master.run_command(
                ['ipa', 'group-add-member', group1, '--groups', group2])
            self.assert_is_member_of_groups(group2, [group1])
            self.assert_group_members_equal(group2, [])
            self.assert_is_member_of_groups(group1, [])
            self.assert_group_members_equal(group1, [user1.cn, group2])

            # user removed from group
            self.master.run_command(
                ['ipa', 'group-remove-member', group1, '--users', user1.login])
            self.assert_is_member_of_groups(user1.cn, ['ipausers'])
            self.assert_group_members_equal(group1, [group2])

            # group removed from another group
            self.master.run_command(
                ['ipa', 'group-remove-member', group1, '--groups', group2])
            self.assert_is_member_of_groups(group2, [])
            self.assert_group_members_equal(group2, [])
            self.assert_is_member_of_groups(group1, [])
            self.assert_group_members_equal(group1, [])

            # user being member of group is deleted
            self.master.run_command(
                ['ipa', 'group-add-member', group1, '--users', user1.login])
            self.assert_is_member_of_groups(user1.cn,
                                            ['ipausers', group1])
            self.assert_group_members_equal(group1, [user1.cn])
            tasks.user_del(self.master, user1.login)
            self.assert_does_not_exist_in_gc(user1.cn)
            self.assert_group_members_equal(group1, [])

            # group being member of another group and containing user and
            # group is deleted
            tasks.group_add(self.master, group3)
            tasks.user_add(self.master, user1.login,
                           user1.first, user1.last)
            self.master.run_command([
                'ipa', 'group-add-member', group2, '--users', user1.login,
                '--groups', group1])
            self.master.run_command([
                'ipa', 'group-add-member', group3, '--groups', group2])
            self.assert_group_members_equal(group1, [])
            self.assert_group_members_equal(group2, [group1, user1.cn])
            self.assert_group_members_equal(group3, [group2])
            self.assert_is_member_of_groups(user1.cn, ['ipausers', group2, group3])
            self.assert_is_member_of_groups(group1, [group2, group3])
            self.assert_is_member_of_groups(group2, [group3])
            self.assert_is_member_of_groups(group3, [])
            tasks.group_del(self.master, group2)
            self.assert_does_not_exist_in_gc(group2)
            self.assert_group_members_equal(group1, [])
            self.assert_group_members_equal(group3, [])
            self.assert_is_member_of_groups(user1.cn, ['ipausers'])
            self.assert_is_member_of_groups(group1, [])
            self.assert_is_member_of_groups(group3, [])
        finally:
            tasks.user_del(self.master, user1.login, ignore_not_exists=True)
            for group in [group1, group2, group3]:
                tasks.group_del(self.master, group, ignore_not_exists=True)
        self.assert_does_not_exist_in_gc(user1.cn)
        self.assert_does_not_exist_in_gc(group1)
        self.assert_does_not_exist_in_gc(group2)
        self.assert_does_not_exist_in_gc(group3)

    @pytest.mark.parametrize([
        'group_add_args', 'expected_group_type'], [

        pytest.param([], {'ACCOUNT_GROUP', 'SECURITY_ENABLED'},
                     id='posix -> global'),
        pytest.param(['--nonposix'], {'ACCOUNT_GROUP'},
                     id='non-posix -> global distribution'),
        pytest.param(['--external'], {'RESOURCE_GROUP', 'SECURITY_ENABLED'},
                     id='external -> domain-local')
    ])
    def test_group_type_value(self, group_add_args, expected_group_type):
        group_name = 'test_group_type'
        tasks.group_add(self.master, group_name, group_add_args)
        try:
            record = self.get_gc_record(group_name)
            assert len(record[1]['groupType']) == 1
            assert (decode_ad_group_type(record[1]['groupType'][0]) ==
                    expected_group_type)
        finally:
            self.master.run_command(['ipa', 'group-del', group_name],
                                    ok_returncode=[0, 2])

    def test_gc_updated_when_changes_synced_from_replica(self):
        user = SimpleTestUser('Replica', 'Sync')
        tasks.user_add(self.replica, user.login, user.first, user.last)
        try:
            self.assert_exists_in_gc(user.cn)
            tasks.user_del(self.replica, user.login)
            self.assert_does_not_exist_in_gc(user.cn)
        finally:
            tasks.user_del(self.replica, user.login, ignore_not_exists=True)


    @pytest.mark.parametrize('daemons', [
        pytest.param(['dirsrv main'], id='main dirsrv'),
        pytest.param(['dirsrv gc'], id='GC dirsrv'),
        pytest.param(['dirsrv main', 'dirsrv gc'], id='both dirsrvs'),
        pytest.param(['gcsyncd'], id='gcsyncd'),
        pytest.param(['dirsrv main', 'dirsrv gc', 'gcsyncd'], id='all')
    ])
    def test_syncd_reconnects_after_daemons_restart(self, daemons):
        services = {
            'dirsrv main': self.main_dirsrv_service,
            'dirsrv gc': gc_dirsrv_service,
            'gcsyncd': gcsyncd_service
        }
        user = SimpleTestUser('Test', 'Reconnects')
        for daemon in daemons:
            self.master.run_command(['systemctl', 'stop', services[daemon]])
        try:
            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                for daemon in daemons:
                    self.master.run_command(
                        ['systemctl', 'start', services[daemon]])
                if 'dirsrv main' in daemons or 'gcsyncd' in daemons:
                    assert wait_for(
                        lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 90)
                tasks.user_add(self.master, user.login, user.first,
                               user.last)
                self.assert_exists_in_gc(user.cn)
        finally:
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

    def test_syncd_reconnects_after_ipactl_restart(self):
        user = SimpleTestUser('Test', 'ReconnectsIpactlRestart')
        try:
            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                self.master.run_command(['ipactl', 'restart'])
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 90)
                tasks.user_add(self.master, user.login, user.first,
                               user.last)
                self.assert_exists_in_gc(user.cn)
        finally:
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

    def check_sync_on_startup(self, action, check, cleanup, service_name):
        service = {
            'dirsrv gc': gc_dirsrv_service,
            'gcsyncd': gcsyncd_service
        }[service_name]

        self.master.run_command(['systemctl', 'stop', service])
        action()
        try:
            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                self.master.run_command(['systemctl', 'start', service])
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 90)
                log = get_log_tail()
                check()
                # allow sync daemon to process possible changes after startup
                time.sleep(10)
                assert not get_changes_in_gc_log(
                    log[log.index(LOG_MESSAGE_GC_INITIALIZED):])
        finally:
            cleanup()

    @pytest.mark.parametrize('service_name', ['dirsrv gc', 'gcsyncd'])
    def test_sync_on_startup_user_created(self, service_name):
        user = SimpleTestUser('Startupsync', 'Usercreate')

        def action():
            tasks.user_add(self.master, user.login, user.first, user.last)

        def check():
            self.assert_is_member_of_groups(user.cn, ['ipausers'])

        def cleanup():
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

        self.check_sync_on_startup(action, check, cleanup, service_name)

    @pytest.mark.parametrize('service_name', ['dirsrv gc', 'gcsyncd'])
    def test_sync_on_startup_user_created_and_deleted(self, service_name):
        user = SimpleTestUser('Startupsync', 'Usercreate')

        def action():
            tasks.user_add(self.master, user.login, user.first, user.last)
            tasks.user_del(self.master, user.login)

        def check():
            self.assert_does_not_exist_in_gc(user.cn)

        def cleanup():
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

        self.check_sync_on_startup(action, check, cleanup, service_name)

    @pytest.mark.parametrize('service_name', ['dirsrv gc', 'gcsyncd'])
    def test_sync_on_startup_user_group_member(self, service_name):
        user = SimpleTestUser('Startupsync', 'Usergroupmember')
        group = 'startupsyncusermember'

        def action():
            tasks.user_add(self.master, user.login, user.first, user.last)
            tasks.group_add(self.master, group)
            self.master.run_command(['ipa', 'group-add-member', group,
                                     '--users', user.login])

        def check():
            self.assert_is_member_of_groups(user.cn, ['ipausers', group])
            self.assert_group_members_equal(group, [user.cn])

        def cleanup():
            tasks.user_del(self.master, user.login, ignore_not_exists=True)
            tasks.group_del(self.master, group, ignore_not_exists=True)

        self.check_sync_on_startup(action, check, cleanup, service_name)

    @pytest.mark.parametrize('service_name', [
        pytest.param('dirsrv gc'),
        pytest.param('gcsyncd', marks=pytest.mark.skip(
            reason='https://github.com/abbra/freeipa/issues/60'))
    ])
    def test_sync_on_startup_complex(self, service_name):
        user1 = SimpleTestUser('Startupsync', 'Complex1')
        user2 = SimpleTestUser('Startupsync', 'Complex2')
        group = 'startupsynccomplex'

        def action():
            tasks.user_add(self.master, user1.login, user1.first, user1.last)
            tasks.user_add(self.master, user2.login, user2.first, user2.last)
            tasks.user_del(self.master, user1.login)
            tasks.group_add(self.master, group)
            self.master.run_command(['ipa', 'group-add-member', group,
                                     '--users', user2.login])

        def check():
            self.assert_does_not_exist_in_gc(user1.cn)
            self.assert_is_member_of_groups(user2.cn, ['ipausers', group])
            self.assert_group_members_equal(group, [user2.cn])

        def cleanup():
            tasks.user_del(self.master, user1.login, ignore_not_exists=True)
            tasks.user_del(self.master, user2.login, ignore_not_exists=True)
            tasks.group_del(self.master, group, ignore_not_exists=True)

        self.check_sync_on_startup(action, check, cleanup, service_name)

    def test_repeated_adtrust_install(self):
        user1 = SimpleTestUser('RepeatedInstall', 'First')
        user2 = SimpleTestUser('RepeatedInstall', 'Second')
        try:
            tasks.user_add(self.master, user1.login, user1.first, user1.last)
            self.assert_exists_in_gc(user1.cn)
            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                res = self.master.run_command([
                    'ipa-adtrust-install', '-U',
                    '-a', self.master.config.admin_password])
                assert ('Global Catalog already installed, skipping'
                        in res.stdout_text)
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 90)

                log = get_log_tail()
                assert log.count(LOG_MESSAGE_GC_INITIALIZED) == 1
                # FIXME: uncomment when https://github.com/abbra/freeipa/issues/56 is fixed
                # assert not get_changes_in_gc_log(log)
                error_to_ignore = "Can't contact LDAP server"
                errors = [s for s in log.splitlines() if 'ERROR' in s and
                          error_to_ignore not in s]
                assert not errors

            self.assert_exists_in_gc(user1.cn)
            tasks.user_add(self.master, user2.login, user2.first, user2.last)
            self.assert_exists_in_gc(user2.cn)
        finally:
            tasks.user_del(self.master, user1.login, ignore_not_exists=True)
            tasks.user_del(self.master, user2.login, ignore_not_exists=True)

    def test_gc_services_managed_by_ipactl(self):
        assert is_service_active(self.master, gc_dirsrv_service)
        assert is_service_active(self.master, gcsyncd_service)
        self.master.run_command(['ipactl', 'stop'])
        assert not is_service_active(self.master, gc_dirsrv_service)
        assert not is_service_active(self.master, gcsyncd_service)
        with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
            self.master.run_command(['ipactl', 'start'])
            assert is_service_active(self.master, gc_dirsrv_service)
            assert is_service_active(self.master, gcsyncd_service)
            assert wait_for(
                lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 90)

    def test_no_changes_during_restart_after_user_added(self):
        user = SimpleTestUser('Restart', 'Changes')
        cookie1 = self.validate_and_parse_gcsync_cookie()
        try:
            tasks.user_add(self.master, user.login, user.first, user.last)
            self.assert_exists_in_gc(user.cn)
            self.master.run_command(['systemctl', 'stop', gcsyncd_service])
            cookie2 = self.validate_and_parse_gcsync_cookie()
            assert cookie2 > cookie1
            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                self.master.run_command(['systemctl', 'start', gcsyncd_service])
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 30)
                # allow sync daemon to process possible changes after startup
                time.sleep(10)
                log = get_log_tail()
                assert not get_changes_in_gc_log(log)
        finally:
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

    def test_cookie_file_is_updated_when_gcsync_stopped(self):
        user = SimpleTestUser('CookieUpdated', 'OnStop')
        cookie1 = self.validate_and_parse_gcsync_cookie()
        try:
            # trigger GC update to increase cookie number
            tasks.user_add(self.master, user.login, user.first, user.last)
            self.assert_exists_in_gc(user.cn)

            self.master.run_command(['systemctl', 'stop', gcsyncd_service])
            cookie2 = self.validate_and_parse_gcsync_cookie()
            assert cookie2 > cookie1
        finally:
            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                self.master.run_command(['systemctl', 'start', gcsyncd_service])
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 30)
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

    def test_cookie_file_is_updated_when_gcsync_restarted(self):
        user = SimpleTestUser('CookieUpdated', 'OnRestart')
        cookie1 = self.validate_and_parse_gcsync_cookie()
        try:
            # trigger GC update to increase cookie number
            tasks.user_add(self.master, user.login, user.first, user.last)
            self.assert_exists_in_gc(user.cn)

            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                self.master.run_command(
                    ['systemctl', 'restart', gcsyncd_service])
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 30)
            cookie2 = self.validate_and_parse_gcsync_cookie()
            assert cookie2 > cookie1
        finally:
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

    def test_cookie_file_is_updated_when_dirsrv_restarted(self):
        user = SimpleTestUser('CookieUpdated', 'OnDsRestart')
        cookie1 = self.validate_and_parse_gcsync_cookie()
        try:
            # trigger GC update to increase cookie number
            tasks.user_add(self.master, user.login, user.first, user.last)
            self.assert_exists_in_gc(user.cn)

            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                self.master.run_command(
                    ['systemctl', 'restart', self.main_dirsrv_service])
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 90)
            cookie2 = self.validate_and_parse_gcsync_cookie()
            assert cookie2 > cookie1
        finally:
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

    def test_cookie_file_is_updated_when_ipa_restarted(self):
        user = SimpleTestUser('CookieUpdated', 'OnIpaRestart')
        cookie1 = self.validate_and_parse_gcsync_cookie()
        try:
            # trigger GC update to increase cookie number
            tasks.user_add(self.master, user.login, user.first, user.last)
            self.assert_exists_in_gc(user.cn)

            with log_tail(self.master, paths.GCSYNCD_LOG) as get_log_tail:
                self.master.run_command(['ipactl', 'restart'])
                assert wait_for(
                    lambda: LOG_MESSAGE_GC_INITIALIZED in get_log_tail(), 90)
            cookie2 = self.validate_and_parse_gcsync_cookie()
            assert cookie2 > cookie1
        finally:
            tasks.user_del(self.master, user.login, ignore_not_exists=True)

    def check_windows_logon_via_autologon(self, host, user, password, domain,
                                          expected_user):
        path = r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        windows_tasks.registry_add(
            host, path, 'DefaultUserName', user, 'REG_SZ')
        windows_tasks.registry_add(
            host, path, 'DefaultPassword', password, 'REG_SZ')
        if domain:
            windows_tasks.registry_add(
                host, path, 'DefaultDomainName', domain, 'REG_SZ')
        else:
            windows_tasks.registry_delete(
                host, path, 'DefaultDomainName', ignore_missing=True)
        windows_tasks.registry_add(host, path, 'AutoAdminLogon', '1', 'REG_SZ')
        windows_tasks.reboot(host)
        wait_for(lambda: get_windows_logged_on_user(host), 30)
        assert (str(get_windows_logged_on_user(host)).lower() ==
                expected_user.lower())

    _login_test_user_name = None
    @property
    def login_test_user_name(self):
        if self._login_test_user_name is None:
            letters = string.ascii_lowercase
            rand_str = ''.join(random.choice(letters) for _ in range(6))
            self._login_test_user_name = 'logintest_' + rand_str
        return self._login_test_user_name

    login_test_user_password = 'loginTestSecret123'

    def modify_string_case(self, s, modify):
        method = {
            'lower': s.lower,
            'upper': s.upper,
            'mixed': s.title,
        }[modify]
        return method()

    def get_user_name_string_for_login_test(self, case):
        return self.modify_string_case(self.login_test_user_name, case)

    def get_domain_name_string_for_login_test(self, domain_case, abbreviated):
        domain = self.master.domain.name
        if abbreviated:
            domain = domain.split('.')[0]
        return self.modify_string_case(domain, domain_case)

    def get_login_string_for_login_test(
            self, login_string_format, user_name_case, domain_name_case,
            domain_name_abbreviated):
        template = {
            'upn': '{user}@{domain}',
            'down-level': r'{domain}\{user}'
        }[login_string_format]
        user = self.get_user_name_string_for_login_test(user_name_case)
        domain = self.get_domain_name_string_for_login_test(
            domain_name_case, domain_name_abbreviated)
        return template.format(user=user, domain=domain)

    @contextmanager
    def user_for_login_test(self, windows_host, windows_local_groups):
        login = self.login_test_user_name
        tasks.create_active_user(self.master, login, self.login_test_user_password,
                                 first=login, last='LoginTest')
        if windows_local_groups:
            username = self.get_login_string_for_login_test(
                'down-level', 'lower', 'upper', False)
            for group in windows_local_groups:
                windows_tasks.add_user_to_local_group(
                    windows_host, username, group)
        try:
            yield
        finally:
            if windows_local_groups:
                username = self.get_login_string_for_login_test(
                    'down-level', 'lower', 'upper', False)
                for group in windows_local_groups:
                    windows_tasks.remove_user_from_local_group(
                        windows_host, username, group)
            tasks.user_del(self.master, self.login_test_user_name)

    @pytest.mark.parametrize('hostname', ['ad_controller', 'ad_client'])
    @pytest.mark.parametrize(
        ['user_case', 'domain_case', 'domain_abbreviated'], [

        pytest.param('lower', 'lower', False, id='user, ipa.test',
                     marks=pytest.mark.skip(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
        pytest.param('lower', 'upper', False, id='user, IPA.TEST'),
        pytest.param('lower', 'mixed', False, id='user, Ipa.Test',
                     marks=pytest.mark.skip(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
        pytest.param('lower', 'lower', True, id='user, ipa',
                     marks=pytest.mark.skip(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
        pytest.param('lower', 'upper', True, id='user, IPA',
                     marks=pytest.mark.skip(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
        pytest.param('lower', 'mixed', True, id='user, Ipa',
                     marks=pytest.mark.skip(reason='https://github.com/abbra/freeipa/issues/65', strict=True)),
        pytest.param('upper', 'upper', False, id='USER, IPA.TEST'),
        pytest.param('mixed', 'upper', False, id='User, IPA.TEST'),
    ])
    def test_login_via_autologon_with_defaultdomain(
            self, hostname, user_case, domain_case, domain_abbreviated):
        host = getattr(self, hostname)
        username = self.get_user_name_string_for_login_test(user_case)
        domain = self.get_domain_name_string_for_login_test(
            domain_case, domain_abbreviated)
        expected_username = self.get_login_string_for_login_test(
            'down-level', 'lower', 'lower', True)
        with self.user_for_login_test(host,
            ['Administrators'] if hostname == 'ad_controller' else None):
            self.check_windows_logon_via_autologon(
                host, username, self.login_test_user_password, domain,
                expected_username)

    @pytest.mark.parametrize('hostname', ['ad_controller', 'ad_client'])
    @parametrize_login_formats
    def test_login_via_autologon_without_defaultdomain(
            self, hostname, login_format, user_case, domain_case,
            domain_abbreviated):
        host = getattr(self, hostname)
        username = self.get_login_string_for_login_test(
            login_format, user_case, domain_case, domain_abbreviated)
        expected_username = self.get_login_string_for_login_test(
            'down-level', 'lower', 'lower', True)
        with self.user_for_login_test(host,
            ['Administrators'] if hostname == 'ad_controller' else None):
            self.check_windows_logon_via_autologon(
                host, username, self.login_test_user_password, None,
                expected_username)

    @pytest.mark.parametrize('hostname', ['ad_controller', 'ad_client'])
    @pytest.mark.parametrize([
        'login_format', 'user_case', 'domain_case','domain_abbreviated'], [

        pytest.param('upn', 'lower', 'lower', False, id='user@ipa.test'),
        pytest.param('upn', 'lower', 'upper', False, id='user@IPA.TEST'),
        pytest.param('upn', 'lower', 'mixed', False, id='user@Ipa.Test'),

        pytest.param('upn', 'lower', 'lower', True, id='user@ipa', marks=pytest.mark.skip(
            reason='https://gitlab.com/samba-team/samba/-/merge_requests/1677', strict=True)),
        pytest.param('upn', 'lower', 'upper', True, id='user@IPA', marks=pytest.mark.skipl(
            reason='https://gitlab.com/samba-team/samba/-/merge_requests/1677', strict=True)),
        pytest.param('upn', 'lower', 'mixed', True, id='user@Ipa', marks=pytest.mark.skipl(
            reason='https://gitlab.com/samba-team/samba/-/merge_requests/1677', strict=True)),

        pytest.param('down-level', 'lower', 'lower', False, id='ipa.test\\user'),
        pytest.param('down-level', 'lower', 'upper', False, id='IPA.TEST\\user'),
        pytest.param('down-level', 'lower', 'mixed', False, id='Ipa.Test\\user'),

        pytest.param('down-level', 'lower', 'lower', True, id='ipa\\user'),
        pytest.param('down-level', 'lower', 'upper', True, id='IPA\\user'),
        pytest.param('down-level', 'lower', 'mixed', True, id='Ipa\\user'),

        pytest.param('upn', 'upper', 'lower', False, id='USER@ipa.test'),
        pytest.param('upn', 'mixed', 'lower', False, id='User@ipa.test'),

        pytest.param('down-level', 'upper', 'upper', False, id='IPA.TEST\\USER'),
        pytest.param('down-level', 'mixed', 'upper', False, id='IPA.TEST\\User'),
    ])
    def test_login_via_winrm_from_linux_with_password(
            self, hostname, login_format, user_case, domain_case,
            domain_abbreviated):
        host = getattr(self, hostname)
        username = self.get_login_string_for_login_test(
            login_format, user_case, domain_case, domain_abbreviated)

        with self.user_for_login_test(host, ['Administrators']):
            session = winrm.Session(
                    host.external_hostname,
                    (username, self.login_test_user_password), transport='ntlm')
            res = session.run_cmd('whoami')
            assert res.std_out.decode('utf-8').strip() == self.get_login_string_for_login_test('down-level', 'lower', 'lower', False)

    @pytest.mark.parametrize('target_host', ['ad_controller', 'ad_client'])
    @pytest.mark.parametrize('src_host', ['master', 'client'])
    def test_login_via_winrm_from_linux_with_kerberos_ticket(self, src_host, target_host):
        src_host = getattr(self, src_host)
        target_host = getattr(self, target_host)
        script = textwrap.dedent('''
            import winrm
            sess = winrm.Session('{host}', ('{user}', ''), transport='kerberos')
            res = sess.run_cmd('whoami')
            print(res.std_out.decode('utf-8'))
        '''.format(host=target_host.hostname,
                   user=self.get_login_string_for_login_test(
                       'upn', 'lower', 'upper', False)))
        with self.user_for_login_test(target_host, ['Administrators']):
            tasks.kinit_as_user(src_host, self.login_test_user_name,
                                self.login_test_user_password)
            res = src_host.run_command(['python', '-c', script])
            assert res.stdout_text.strip() == self.get_login_string_for_login_test('down-level', 'lower', 'lower', True)

    @pytest.mark.parametrize(
        ['src_host', 'target_host'],
        [['ad_controller', 'ad_client'], ['ad_client', 'ad_controller']])
    @parametrize_login_formats
    def test_login_via_winrm_from_windows(self, src_host, target_host,
                                          login_format, user_case, domain_case,
                                          domain_abbreviated):
        src_host = getattr(self, src_host)
        target_host = getattr(self, target_host)
        with self.user_for_login_test(target_host, ['Administrators']):
            username = self.get_login_string_for_login_test(
                login_format, user_case, domain_case, domain_abbreviated)
            winrs_cmd = ['winrs.exe',
                         '-r:{}'.format(target_host.hostname),
                         '-u:{}'.format(username),
                         '-p:{}'.format(self.login_test_user_password)]
            res = windows_tasks.winrm_run_command(
                src_host, winrs_cmd + ['whoami'])
            expected = self.get_login_string_for_login_test(
                'down-level', 'lower', 'lower', True)
            assert res.stdout_text.strip() == expected
