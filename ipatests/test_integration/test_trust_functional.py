# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import time

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestHBAC(IntegrationTest):
    topology = 'line'
    num_clients = 1
    num_ad_domains = 1
    ad_user_login = 'nonposixuser'
    ad_user_password = 'Secret123'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_client(cls.master, cls.clients[0])
        cls.ad = cls.ads[0]
        cls.ad_user = '{}@{}'.format(cls.ad_user_login, cls.ad.domain.name)

        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.configure_windows_dns_for_trust(cls.ad, cls.master)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name,
                                      extra_args=['--range-type=ipa-ad-trust',
                                                  '--two-way=true']
                                      )

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_hbac(self):
        hrule = "hbacrule_11"
        srule = "sudorule_11"
        tasks.clear_sssd_cache(self.master)
        try:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            tasks.group_add(self.master, groupname="hbacgroup_external",
                            extra_args=["--external"])
            tasks.group_add(self.master, groupname="hbacgroup")
            tasks.group_add_member(self.master, groupname="hbacgroup",
                                   extra_args=['--groups=hbacgroup_external'])
            self.master.run_command([
                'ipa', '-n', 'group-add-member', '--external',
                self.ad_user, 'hbacgroup_external'])

            self.master.run_command(
                ["ipa", "hbacrule-enable", "allow_all"])
            self.master.run_command(
                ["ipa", "hbacrule-add", hrule, "--hostcat=all"])
            self.master.run_command(
                ["ipa", "hbacrule-add-service", hrule, "--hbacsvcs=sudo"])
            self.master.run_command(
                ["ipa", "hbacrule-add-user", hrule, "--groups=hbacgroup"])
            self.master.run_command(
                ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"])
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--groups=hbacgroup"])
            tasks.clear_sssd_cache(self.master)
            tasks.clear_sssd_cache(self.clients[0])
            time.sleep(30)
            test_sudo = "su {0} -c 'sudo -S id'".format(self.ad_user)
            self.clients[0].run_command(test_sudo,
                                        stdin_text='Secret123')
            self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
            tasks.clear_sssd_cache(self.master)
            tasks.clear_sssd_cache(self.clients[0])
            time.sleep(30)
            self.clients[0].run_command(test_sudo,
                                        stdin_text='Secret123')
        finally:
            tasks.clear_sssd_cache(self.master)
