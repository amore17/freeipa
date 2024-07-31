import time

from ipatests.pytest_ipa.integration import config
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
import os
from ipalib.constants import MAX_DOMAIN_LEVEL


def install_master():
    conf = config.Config.from_env(os.environ)
    main_dom = conf.domains[0]
    trusted_dom = conf.domains[1]
    #ad_dom = conf.domains[2]


    for host in (main_dom.master, trusted_dom.master):
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
    #tasks.install_client(main_dom.master, main_dom.clients[0])
    #tasks.install_client(trusted_dom.master, trusted_dom.clients[0])

class TestMinimalConfig(IntegrationTest):
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

    def test_install_multidomain_master(self):
        install_master()

    def test_prep_trust_multidomain_master(self):
        conf = config.Config.from_env(os.environ)
        master1 = conf.domains[0].master
        master2 = conf.domains[1].master
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
        rangename1 = master1.domain.name.upper() + '_id_range'
        rangename2 = master2.domain.name.upper() + '_id_range'
        master1.run_command(["ipa", "idrange-show", rangename1 , "--raw"])
        master1.run_command(["ipa", "trustconfig-show", "--raw"])

        master2.run_command(["ipa", "idrange-show", rangename2 , "--raw"])
        master2.run_command(["ipa", "trustconfig-show", "--raw"])

    def test_add_trust_multidomain_master(self):
        """
        Establish trust between IPA1.TEST and IPA2.TEST
        """
        conf = config.Config.from_env(os.environ)
        master1 = conf.domains[0].master
        master2 = conf.domains[1].master
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

    def test_trusted_user(self):
        """
        Establish trust between IPA1.TEST and IPA2.TEST
        """
        conf = config.Config.from_env(os.environ)
        master1 = conf.domains[0].master
        master2 = conf.domains[1].master
        rangename1 = master1.domain.name.upper() + '_id_range'
        idrange_show = master1.run_command(["ipa", "idrange-show", rangename1 , "--raw"])
        trust_config_show = master1.run_command(["ipa", "trustconfig-show", "--raw"])
        info1 = self._parse_result(idrange_show)
        info2 = self._parse_result(trust_config_show)

        assert info1["iparangetype"] == "ipa-local"
        ipabaseid = info1["ipabaseid"]
        ipaidrangesize = info1["ipaidrangesize"]
        ipantsecurityidentifier = info2["ipantsecurityidentifier"]

        add_idrange = ["ipa", "idrange-add", rangename1,
                       "--dom-sid={0}".format(ipantsecurityidentifier),
                       "--type=ipa-ad-trust-posix", "--base-id={0}".format(ipabaseid),
                       "--range-size={0}".format(ipaidrangesize)
                       ]
        master2.run_command(add_idrange)
        tasks.clear_sssd_cache(master1)
        tasks.clear_sssd_cache(master2)
        time.sleep(10)
        master1.run_command(["id", "idmuser@{0}".format(master2.domain.name)])
        master2.run_command(["id", "idmuser@{0}".format(master1.domain.name)])
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
