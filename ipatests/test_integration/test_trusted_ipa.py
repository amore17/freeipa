import time
import pytest
from ipatests.pytest_ipa.integration import config
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
import os

def install_multidomain(master, trusted_master):
    for host in (master, trusted_master):
        tasks.install_master(host, setup_dns=True)
        user = "idmuser"
        passwd = "Secret123"
        group = "idmgroup"
        tasks.kinit_admin(host)
        tasks.create_active_user(
            host, user, passwd, first=user, last=user
        )
        tasks.kinit_admin(host)
        tasks.group_add(host, group)
        tasks.group_add_member(host, group, user)

class TestMinimalConfig(IntegrationTest):
    num_trusted_domains = 1
    num_clients = 1
    num_trusted_clients = 1

    @classmethod
    def install(cls, mh):
        master1 = cls.master
        master2 = cls.trusted_master
        cls.client = cls.clients[0]
        cls.trusted_client = cls.trusted_clients[0]

        master1.run_command(["hostname"])
        master2.run_command(["hostname"])

    @classmethod
    def uninstall(cls, mh):
        pass

    def _parse_result(self, result):
        # ipa CLI should get an --outform json option
        info = {}
        for line in result.stdout_text.split("\n"):
            line = line.strip()
            if line:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                try:
                    v = int(v, 10)
                except ValueError:
                    if v == "FALSE":
                        v = False
                    elif v == "TRUE":
                        v = True
                info.setdefault(k.lower(), []).append(v)

        for k, v in info.items():
            if len(v) == 1:
                info[k] = v[0]
            else:
                info[k] = set(v)
        return info

    def test_multidomain_setup(self):
        install_multidomain(self.master, self.trusted_master)
        tasks.install_client(self.master, self.client)
        tasks.install_client(self.trusted_master, self.trusted_client)
        master1 = self.master
        master2 = self.trusted_master
        tasks.kinit_admin(master1)
        tasks.kinit_admin(master2)
        tasks.disable_dnssec_validation(master1)
        tasks.disable_dnssec_validation(master2)
        tasks.restart_named(master1)
        master1.run_command(
            ["ipa", "dnsforwardzone-add", master2.domain.name,
             "--forwarder={0}".format(master2.ip),
             "--forward-policy=only"
             ]
        )
        master2.run_command(
            ["ipa", "dnsforwardzone-add", master1.domain.name,
             "--forwarder={0}".format(master1.ip),
             "--forward-policy=only"
             ]
        )

    def test_add_trust_multidomain_master(self):
        """
        Establish trust between IPA1.TEST and IPA2.TEST
        """
        master1 = self.master
        master2 = self.trusted_master
        tasks.kinit_admin(master1)
        tasks.install_adtrust(master1)
        tasks.install_adtrust(master2)
        cmd = ["ipa", "trust-add", "--type=ad",
               master2.domain.name, "--admin",
               "admin@{0}".format(master2.domain.name.upper()),
               "--range-type=ipa-ad-trust-posix",
               "--password", "--two-way=true"
               ]
        master1.run_command(cmd, stdin_text=master2.config.admin_password)
        master1.run_command(["ipa", "idrange-find"], raiseonerr=False)
        master2.run_command(["ipa", "idrange-find"], raiseonerr=False)

    def test_trusted_user_kinit(self):
        """
        Verify that truster user kinit is working.
        """
        master1 = self.master
        master2 = self.trusted_master

        rangename1 = master1.domain.name.upper() + '_id_range'
        idrange_show1 = master1.run_command(["ipa", "idrange-show", rangename1 , "--raw"])
        trust_config_show1 = master1.run_command(["ipa", "trustconfig-show", "--raw"])
        info1 = self._parse_result(idrange_show1)
        info2 = self._parse_result(trust_config_show1)
        assert info1["iparangetype"] == "ipa-local"
        ipabaseid1 = info1["ipabaseid"]
        ipaidrangesize1 = info1["ipaidrangesize"]
        ipantsecurityidentifier1 = info2["ipantsecurityidentifier"]

        add_idrange = ["ipa", "idrange-add", rangename1,
                       "--dom-sid={0}".format(ipantsecurityidentifier1),
                       "--type=ipa-ad-trust-posix", "--base-id={0}".format(ipabaseid1),
                       "--range-size={0}".format(ipaidrangesize1)
                       ]
        master2.run_command(add_idrange)
        cmd2 = ["ipa", "trust-mod", master1.domain.name.upper(), "--addattr",
                "objectclass=ipatrustobject",
                "--addattr", "ipapartnertrusttype=35"
                ]
        master2.run_command(cmd2)
        tasks.clear_sssd_cache(master1)
        tasks.clear_sssd_cache(master2)
        time.sleep(10)
        user = "idmuser"
        passwd = "Secret123"
        tasks.kinit_as_user(
            master1,
            user='{0}@{1}'.format(user, master2.domain.name.upper()),
            password=passwd
        )
        tasks.kinit_as_user(
            master2,
            user='{0}@{1}'.format(user, master1.domain.name.upper()),
            password=passwd
        )

    def test_trusted_user_id(self):
        """
        Verify that truster user kinit is working.
        """
        master1 = self.master
        master2 = self.trusted_master
        master1.run_command(["ipa", "idrange-find"])
        master2.run_command(["ipa", "idrange-find"])
        master1.run_command(["id", "idmuser@{0}".format(master2.domain.name)], raiseonerr=False)
        master2.run_command(["id", "idmuser@{0}".format(master1.domain.name)], raiseonerr=False)

    @pytest.fixture
    def hbac_setup_teardown(self):
        # allow sshd only on given host
        master1 = self.master
        master2 = self.trusted_master
        tasks.kinit_admin(master1)
        tasks.kinit_admin(master2)
        idmuser = "idmuser@{0}".format(master2.domain.name)

        master1.run_command(["ipa", "group-add", "--desc=0", "hbacgroup_external", "--external"])
        master1.run_command(["ipa", "group-add", "--desc=0", "hbacgroup"])
        master1.run_command(["ipa", "group-add-member", "hbacgroup", "--groups=hbacgroup_external"])

        master1.run_command(["id", idmuser])
        hcmd = "ipa group-add-member hbacgroup_external --external='{0}' --users='' --groups=''".format(idmuser)
        master1.run_command(hcmd)
        master1.run_command(["ipa", "hbacrule-add-host", "rule1",
                             "--hosts", self.client])
        master1.run_command(["ipa", "hbacrule-add-service", "rule1", "--hbacsvcs=sshd"])
        master1.run_command(["ipa", "hbacrule-add-user", "rule1", "--groups=hbacgroup"])
        master1.run_command(["ipa", "hbacrule-disable", "allow_all"])

        master1.run_command(["id", idmuser])
        tasks.clear_sssd_cache(master1)
        tasks.clear_sssd_cache(self.client)
        yield

        # cleanup
        tasks.kinit_admin(master1)
        master1.run_command(["ipa", "hbacrule-enable", "allow_all"])
        master1.run_command(["ipa", "hbacrule-del", "rule1"])

    def test_auth_hbac(self):
        """
        Test case to check that hbacrule is working as
        expected for trusted domain user.
        """
        master1 = self.master
        master2 = self.trusted_master
        idmuser = "idmuser@{0}".format(master2.domain.name)
        tasks.kdestroy_all(master1)
        tasks.kinit_as_user(
            master1,
            user=idmuser,
            password="Secret123"
        )
        ssh_cmd = "ssh -q -K -l {0} {1} whoami"
        client_ssh = master1.run_command(
            ssh_cmd.format(idmuser, self.client)
        )
        assert "idmuser" in client_ssh.stdout_text
        master_ssh = master1.run_command(
            ssh_cmd.format(master1.hostname))
        assert "idmuser" in master_ssh.stdout_text

    def test_auth_sudo_idp(self):
        """
        Test case to check that sudorule is working as
        expected for trusted domain user.
        """
        master1 = self.master
        master2 = self.trusted_master
        tasks.kdestroy_all(master1)
        tasks.kinit_admin(master1)
        #  rule: trusted idmuser is allowed to execute yum on
        #  the client machine as root.
        idmuser = "idmuser@{0}".format(master2.domain.name)
        cmdlist = [
            ["ipa", "sudocmd-add", "/usr/bin/yum"],
            ["ipa", "sudorule-add", "sudorule"],
            ['ipa', 'sudorule-add-user', '--users', idmuser,
             'sudorule'],
            ['ipa', 'sudorule-add-host', '--hosts',
             self.client.hostname, 'sudorule'],
            ['ipa', 'sudorule-add-runasuser',
             '--users=root', 'sudorule'],
            ['ipa', 'sudorule-add-allow-command',
             '--sudocmds=/usr/bin/yum', 'sudorule'],
            ['ipa', 'sudorule-show', 'sudorule', '--all'],
            ['ipa', 'sudorule-add-option',
             'sudorule', '--sudooption', "!authenticate"]
        ]
        for cmd in cmdlist:
            self.master.run_command(cmd)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.client)
        try:
            cmd = 'sudo -ll -U {0}'.format(idmuser)
            test = self.client.run_command(cmd).stdout_text
            assert "/usr/bin/yum" in test
            test_sudo = 'su -c "sudo yum list yum" {0}'.format(idmuser)
            self.client.run_command(test_sudo)
            list_fail = self.master.run_command(cmd).stdout_text
            assert "is not allowed to run sudo" in list_fail
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'sudorule-del', 'sudorule'])
            self.master.run_command(["ipa", "sudocmd-del", "/usr/bin/yum"])
