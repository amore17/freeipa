import pytest
from ipatests.test_integration.base import (
    IntegrationTest, MultiDomainIntegrationTest)
import time
from ipatests.pytest_ipa.integration import tasks
from contextlib import contextmanager
from ipaplatform.paths import paths


class TestIpaClientAutomountDiscoveryHint(MultiDomainIntegrationTest):
    num_replicas = 0
    num_trusted_replicas = 0
    num_clients = 1
    num_trusted_clients = 1
    topology = "line"


    def test_setup_ipa_and_client(self):
        """
        Sets up the FreeIPA master with DNS and enrolls the client.
        Also configures a basic automount map on the master.
        """
        # 1. Install IPA master with DNS
        tasks.kinit_admin(self.master)

        # 2. Configure a basic automount map on the master
        self.master.run_command(['ipa', 'automountmap-add', 'default', 'auto.testmap'])
        self.master.run_command([
            'ipa', 'automountkey-add', 'default', 'auto.testmap', '--key=testdir',
            '--info="-fstype=nfs,rw,soft ' + self.master.domain.name + ':/export/test"'
        ])
        self.master.run_command(['mkdir', '-p', '/export/test'])
        self.master.run_command(['echo', '/export/test *(rw,no_root_squash,sync)', '>', '/etc/exports.d/test.exports'])
        self.master.run_command(['systemctl', 'restart', 'nfs-server'])
        self.master.run_command(['exportfs', '-fva'])

        # 3. Enroll the client *initially* using default DNS discovery
        # This means client's resolv.conf will temporarily include IPA_DOMAIN
        client2 = self.trusted_clients[0]
        tasks.uninstall_client(client2)
        args = [
            'ipa-client-install',
            '--hostname', client2.hostname,
            '--server', self.master.hostname,
            '--domain', self.master.domain.name,
            '--realm', self.master.domain.realm,
            '--fixed-primary', '--mkhomedir',
            '-p', client2.config.admin_name,
            '-w', client2.config.admin_password,
            '-U'
        ]
        client2.run_command(args)
        # Ensure client can resolve master for initial automount if needed later

    @contextmanager
    def reset_client_and_automount_after_test(self):
        """
        Ensures automount is uninstalled and client DNS is reset after each test.
        Configures the client's /etc/resolv.conf to simulate a different local DNS domain.
        The client's nameserver will point to the IPA master's IP, but its search domain
        will be different.
        """
        client2 = self.trusted_clients[0]
        clientdomain = client2.domain.name
        ipadomain = self.master.domain.name
        iparealm = self.master.domain.realm
        ipa_master_ip = self.master.ip
        conf_backup = tasks.FileBackup(self.master, paths.RESOLV_CONF)
        try:
            resolv_conf_content = (
                f"nameserver {ipa_master_ip}\n"
                f"search {clientdomain}\n"
                "# The IPA domain is deliberately NOT in the search path for this test"
            )
            client2.put_file_contents(paths.RESOLV_CONF, resolv_conf_content)
            # Ensure DNS cache is cleared or service restarted for changes to take effect
            client2.run_command(['resolvectl', 'flush-caches'], raiseonerr=False)
            client2.run_command(['systemctl', 'restart', 'systemd-resolved'], raiseonerr=False)
            # Give some time for DNS changes to propagate if services restart
            time.sleep(5)
            yield
        finally:
            conf_backup.restore()
            client2.run_command(['ipa-client-automount', '--uninstall', '--unattended'], raiseonerr=False)
            # Reset resolv.conf to a state where it can talk to IPA DNS properly for next tests
            client2.run_command(['systemctl', 'restart', 'systemd-resolved'], raiseonerr=False)
            client2.run_command(['systemctl', 'restart', 'sssd'], raiseonerr=False)


    def test_automount_fails_without_server_when_dns_differs(self):
        """
        Verifies that ipa-client-automount fails without --server when client's
        DNS search domain is different from IPA domain.
        """
        client2 = self.trusted_clients[0]
        ipadomain = self.master.domain.name

        # Configure client DNS to simulate the cross-domain scenario
        with self.reset_client_and_automount_after_test():
            # Attempt ipa-client-automount without --server
            result = client2.run_command(
                ['ipa-client-automount', '--unattended',
                 '--debug'],
                raiseonerr=False
            )
            assert result.returncode != 0, \
            "ipa-client-automount unexpectedly succeeded without --server when client DNS differs."
            # Look for typical discovery failure messages
            assert "Unable to discover domain" in result.stderr_text or \
                   "DNS discovery failed" in result.stderr_text or \
                   "No IPA servers could be found" in result.stderr_text, \
                f"Expected discovery failure message for automount, but got:\n{result.stderr_text}"


    def test_automount_succeeds_with_domain_hint_when_dns_differs(self):
        """
        Verifies that ipa-client-automount succeeds with a --domain
        when client's DNS search domain is different from IPA domain.
        This test is hypothetical and requires a FreeIPA feature implementation.
        """
        client2 = self.trusted_clients[0]
        clientdomain = client2.domain.name
        ipadomain = self.master.domain.name
        iparealm = self.master.domain.realm


        with self.reset_client_and_automount_after_test():
            result = client2.run_command(
                ['ipa-client-automount', '--unattended', f'--domain={iparealm}'
                 ]
            )
            assert result.returncode == 0, \
                f"ipa-client-automount with --domain failed unexpectedly:\n{result.stderr_text}"

            # Verify automount configuration files are present
            assert client2.transport.file_exists('/etc/auto.master.d/ipa-autofs.conf')
            assert client2.transport.file_exists('/etc/sssd/sssd.conf')

            # Verify autofs service is running
            autofs_status = client2.run_command(['systemctl', 'is-active', 'autofs']).stdout.strip()
            assert autofs_status == 'active', "autofs service should be active after successful automount config."

            # Optionally, try to access the mounted share to confirm full functionality
            client2.kinit('admin') # Need a Kerberos ticket for NFSv4
            client2.run_command(['ls', '/misc/testdir']) # Assuming /misc is base for automounts
