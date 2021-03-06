#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function, absolute_import

import base64
import datetime
import email
import json
import logging
import pytest
import textwrap

from subprocess import CalledProcessError

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

logger = logging.getLogger(__name__)


def datetime_to_generalized_time(dt):
    """Convert datetime to LDAP_GENERALIZED_TIME_FORMAT
       Note: Move into ipalib.
    """
    dt = dt.timetuple()
    generalized_time_str = str(dt.tm_year) + "".join(
        "0" * (2 - len(str(item))) + str(item)
        for item in (dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec,)
    )
    return generalized_time_str + "Z"


def postconf(host, option):
    host.run_command(r"postconf -e '%s'" % option)


def configure_postfix(host, realm):
    """Configure postfix for:
          * SASL auth
          * to be the destination of the IPA domain.
    """
    # Setup the keytab we need for SASL auth
    host.run_command(r"ipa service-add smtp/%s --force" % host.hostname)
    host.run_command(r"ipa-getkeytab -p smtp/%s -k /etc/postfix/smtp.keytab" %
                     host.hostname)
    host.run_command(r"chown root:mail /etc/postfix/smtp.keytab")
    host.run_command(r"chmod 640 /etc/postfix/smtp.keytab")

    # Configure the SASL smtp service to use GSSAPI
    host.run_command(
        r"sed -i 's/plain login/GSSAPI plain login/' /etc/sasl2/smtpd.conf")
    host.run_command(
        r"sed -i 's/MECH=pam/MECH=kerberos5/' /etc/sysconfig/saslauthd")
    postconf(host,
             'import_environment = MAIL_CONFIG MAIL_DEBUG MAIL_LOGTAG TZ '
             'XAUTHORITY DISPLAY LANG=C KRB5_KTNAME=/etc/postfix/smtp.keytab')
    postconf(host,
             'smtpd_client_restrictions = permit_sasl_authenticated, reject')
    postconf(host,
             'smtpd_recipient_restrictions = permit_sasl_authenticated, reject')
    postconf(host,
             'smtpd_sender_restrictions = permit_sasl_authenticated, reject')
    postconf(host, 'smtpd_sasl_auth_enable = yes')
    postconf(host, 'smtpd_sasl_security_options = noanonymous')
    postconf(host,
             'smtpd_sasl_tls_security_options = $smtpd_sasl_security_options')
    postconf(host, 'broken_sasl_auth_clients = yes')
    postconf(host, 'smtpd_sasl_authenticated_header = yes')
    postconf(host, 'smtpd_sasl_local_domain = %s' % realm)

    host.run_command(["systemctl", "restart", "saslauthd"])

    result = host.run_command(["postconf", "mydestination"])
    mydestination = result.stdout_text.strip() + ", " + host.domain.name
    postconf(host, mydestination)

    host.run_command(["systemctl", "restart", "postfix"])


def configure_starttls(host):
    """Obtain a TLS cert for the host and configure postfix for starttls

       Depends on configure_postfix() being executed first.
    """

    host.run_command(r'rm -f /etc/pki/tls/private/postfix.key')
    host.run_command(r'rm -f /etc/pki/tls/certs/postfix.pem')
    host.run_command(["ipa-getcert", "request",
                      "-f", "/etc/pki/tls/certs/postfix.pem",
                      "-k", "/etc/pki/tls/private/postfix.key",
                      "-K", "smtp/%s" % host.hostname,
                      "-D", host.hostname,
                      "-O", "postfix",
                      "-o", "postfix",
                      "-M", "0640",
                      "-m", "0640",
                      "-w",
                      ])
    postconf(host, 'smtpd_tls_loglevel = 1')
    postconf(host, 'smtpd_tls_auth_only = yes')
    postconf(host, 'smtpd_tls_key_file = /etc/pki/tls/private/postfix.key')
    postconf(host, 'smtpd_tls_cert_file = /etc/pki/tls/certs/postfix.pem')
    postconf(host, 'smtpd_tls_received_header = yes')
    postconf(host, 'smtpd_tls_session_cache_timeout = 3600s')

    host.run_command(["systemctl", "restart", "postfix"])


def configure_ssl(host):
    """Enable the ssl listener on port 465.
    """
    conf = host.get_file_contents('/etc/postfix/master.cf',
                                  encoding='utf-8')
    conf += 'smtps inet n - n - - smtpd\n'
    conf += '  -o syslog_name=postfix/smtps\n'
    conf += '  -o smtpd_tls_wrappermode=yes\n'
    conf += '  -o smtpd_sasl_auth_enable=yes\n'
    host.put_file_contents('/etc/postfix/master.cf', conf)

    host.run_command(["systemctl", "restart", "postfix"])


def decode_header(header):
    """Decode the header if needed and return the value"""
    # Only support one value for now
    (value, encoding) = email.header.decode_header(header)[0]
    if encoding:
        return value.decode(encoding)
    else:
        return value


def validate_mail(host, id, content):
    """Retrieve a remote e-mail and determine if it matches the current user"""
    mail = host.get_file_contents('/var/mail/user%d' % id)
    msg = email.message_from_bytes(mail)
    assert decode_header(msg['To']) == 'user%d@%s' % (id, host.domain.name)
    assert decode_header(msg['From']) == 'IPA-EPN <noreply@%s>' % \
                                         host.domain.name
    assert decode_header(msg['subject']) == 'Your password will expire soon.'

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        body = part.get_payload()
        decoded = base64.b64decode(body).decode('utf-8')
        assert content in decoded


class TestEPN(IntegrationTest):
    """Test Suite for EPN: https://pagure.io/freeipa/issue/3687
    """

    num_clients = 1
    notify_ttls = (28, 14, 7, 3, 1)

    def _check_epn_output(
        self,
        host,
        dry_run=False,
        from_nbdays=None,
        to_nbdays=None,
        raiseonerr=True,
    ):
        result = tasks.ipa_epn(host, raiseonerr=raiseonerr, dry_run=dry_run,
                               from_nbdays=from_nbdays,
                               to_nbdays=to_nbdays)
        json.dumps(json.loads(result.stdout_text), ensure_ascii=False)
        return (result.stdout_text, result.stderr_text)

    @classmethod
    def install(cls, mh):
        tasks.install_packages(cls.master, ["postfix"])
        tasks.install_packages(cls.clients[0], ["postfix"])
        for host in (cls.master, cls.clients[0]):
            try:
                tasks.install_packages(host, ["cyrus-sasl"])
            except Exception:
                # the package is likely already installed
                pass
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])
        configure_postfix(cls.master, cls.master.domain.realm)
        configure_postfix(cls.clients[0], cls.master.domain.realm)

    @classmethod
    def uninstall(cls, mh):
        super(TestEPN, cls).uninstall(mh)
        tasks.uninstall_packages(cls.master, ["postfix"])
        tasks.uninstall_packages(cls.clients[0], ["postfix"])
        cls.master.run_command(r'rm -f /etc/postfix/smtp.keytab')
        cls.master.run_command(r'getcert stop-tracking -f '
                               '/etc/pki/tls/certs/postfix.pem')
        cls.master.run_command(r'rm -f /etc/pki/tls/private/postfix.key')
        cls.master.run_command(r'rm -f /etc/pki/tls/certs/postfix.pem')

    @pytest.mark.skip_if_platform(
        "debian", reason="Cannot check installed packages using RPM"
    )
    def test_EPN_config_file(self):
        """Check that the EPN configuration file is installed.
           https://pagure.io/freeipa/issue/8374
        """
        # workaround for https://github.com/freeipa/freeipa-pr-ci/issues/378
        rpm_q_cmds = [
            ["rpm", "-qi", "freeipa-client"],
            ["rpm", "-qi", "freeipa-client-epn"],
            ["rpm", "-qc", "freeipa-client-epn"],
            ["rpm", "-V", "freeipa-client-epn"],
            ["rpm", "-qvc", "freeipa-client-epn"],
            ["ls", "-l", "/etc/ipa", "/etc/ipa/epn"],
        ]
        for cmd in rpm_q_cmds:
            self.master.run_command(cmd, raiseonerr=False)
        tasks.uninstall_packages(self.master, ["*ipa-client-epn"])
        tasks.install_packages(self.master, ["*ipa-client-epn"])
        for cmd in rpm_q_cmds:
            self.master.run_command(cmd, raiseonerr=False)
        # end workaround
        epn_conf = "/etc/ipa/epn.conf"
        epn_template = "/etc/ipa/epn/expire_msg.template"
        cmd1 = self.master.run_command(["rpm", "-qc", "freeipa-client-epn"])
        assert epn_conf in cmd1.stdout_text
        assert epn_template in cmd1.stdout_text
        cmd2 = self.master.run_command(["sha256sum", epn_conf])
        ck = "4c207b5c9c760c36db0d3b2b93da50ea49edcc4002d6d1e7383601f0ec30b957"
        assert cmd2.stdout_text.find(ck) == 0

    def test_EPN_smoketest_1(self):
        """No users except admin. Check --dry-run output.
           With the default configuration, the result should be an empty list.
           Also check behavior on master and client alike.
        """
        epn_conf = textwrap.dedent('''
            [global]
        ''')
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)
        # check EPN on client (LDAP+GSSAPI)
        (stdout_text, unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        assert len(json.loads(stdout_text)) == 0
        # check EPN on master (LDAPI)
        (stdout_text, unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert len(json.loads(stdout_text)) == 0

    @pytest.fixture
    def cleanupusers(self):
        """Fixture to remove any users added as part of the tests.

           It isn't necessary to remove all users created.

           Ignore all errors.
        """
        yield
        for user in ["testuser0", "testuser1"]:
            try:
                self.master.run_command(['ipa', 'user-del', user])
            except Exception:
                pass

    @pytest.fixture
    def cleanupmail(self):
        """Cleanup any existing mail that has been sent."""
        for i in range(30):
            self.master.run_command(["rm", "-f", "/var/mail/user%d" % i])

    def test_EPN_smoketest_2(self, cleanupusers):
        """Add a user without password.
           Add a user whose password expires within the default time range.
           Check --dry-run output.
        """
        tasks.user_add(self.master, "testuser0")
        tasks.user_add(
            self.master,
            "testuser1",
            password="Secret123",
            extra_args=[
                "--password-expiration",
                datetime_to_generalized_time(
                    datetime.datetime.utcnow() + datetime.timedelta(days=7)
                ),
            ],
        )
        (stdout_text_client, unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        (stdout_text_master, unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert stdout_text_master == stdout_text_client
        assert "testuser0" not in stdout_text_client
        assert "testuser1" in stdout_text_client

    def test_EPN_smoketest_3(self):
        """Add a bunch of users with incrementally expiring passwords
           (one per day). Check --dry-run output.
        """

        users = {}
        userbase_str = "user"

        for i in range(30):
            uid = userbase_str + str(i)
            users[i] = dict(
                uid=uid,
                days=i,
                krbpasswordexpiration=datetime_to_generalized_time(
                    datetime.datetime.utcnow() + datetime.timedelta(days=i)
                ),
            )

        for key in users:
            tasks.user_add(
                self.master,
                users[key]["uid"],
                extra_args=[
                    "--password-expiration",
                    users[key]["krbpasswordexpiration"],
                ],
                password=None,
            )

        (stdout_text_client, unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        (stdout_text_master, unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert stdout_text_master == stdout_text_client
        user_lst = []
        for user in json.loads(stdout_text_master):
            user_lst.append(user["uid"])
        expected_users = ["user1", "user3", "user7", "user14", "user28"]
        assert sorted(user_lst) == sorted(expected_users)

    def test_EPN_nbdays(self):
        """Test the to/from nbdays options (implies --dry-run)

           We have a set of users installed with varying expiration
           dates. Confirm that to/from nbdays finds them.
        """

        # Compare the notify_ttls values
        for i in self.notify_ttls:
            user_list = []
            (stdout_text_client, unused) = self._check_epn_output(
                self.clients[0], from_nbdays=i, to_nbdays=i + 1, dry_run=True)
            for user in json.loads(stdout_text_client):
                user_list.append(user["uid"])
            assert len(user_list) == 1
            assert user_list[0] == "user%d" % i

    # From here the tests build on one another:
    #  1) add auth
    #  2) tweak the template
    #  3) add starttls

    def test_EPN_authenticated(self, cleanupmail):
        """Enable authentication and test that mail is delivered
        """
        epn_conf = textwrap.dedent('''
            [global]
            smtp_user={user}
            smtp_password={password}
        '''.format(user=self.master.config.admin_name,
                   password=self.master.config.admin_password))
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\n\nYour password will expire")

    def test_EPN_template(self, cleanupmail):
        """Modify the template to ensure changes are applied.
        """
        exp_msg = textwrap.dedent('''
            Hi {{ first }} {{last}},
            Your login entry {{uid}} is going to expire on
            {{ expiration }}. Please change it soon.

            Your friendly neighborhood admins.
        ''')
        self.master.put_file_contents('/etc/ipa/epn/expire_msg.template',
                                      exp_msg)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\nYour login entry user%d is going" % i)

    def test_mailtest(self, cleanupmail):
        """Execute mailtest to validate mail is working

           Set of of our pre-created users as the smtp_admin to receive
           the mail, run ipa-epn --mailtest, then validate the result.

           Using a non-expired user here, user2, to receive the result.
        """
        epn_conf = textwrap.dedent('''
            [global]
            smtp_user={user}
            smtp_password={password}
            smtp_admin=user2@{domain}
        '''.format(user=self.master.config.admin_name,
                   password=self.master.config.admin_password,
                   domain=self.master.domain.name))
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        tasks.ipa_epn(self.master, mailtest=True)
        validate_mail(self.master, 2,
                      "Hi SAMPLE USER,\nYour login entry SAUSER is going")

    def test_mailtest_dry_run(self):
        try:
            tasks.ipa_epn(self.master, mailtest=True, dry_run=True)
        except CalledProcessError as e:
            assert 'You cannot specify' in e.stderr
        else:
            raise AssertionError('--mail-test and --dry-run aren\'t supposed '
                                 'to succeed')

    def test_EPN_starttls(self, cleanupmail):
        """Configure with starttls and test delivery
        """
        epn_conf = textwrap.dedent('''
            [global]
            smtp_user={user}
            smtp_password={password}
            smtp_security=starttls
        '''.format(user=self.master.config.admin_name,
                   password=self.master.config.admin_password))
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)
        configure_starttls(self.master)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\nYour login entry user%d is going" % i)

    def test_EPN_ssl(self, cleanupmail):
        """Configure with ssl and test delivery
        """
        epn_conf = textwrap.dedent('''
            [global]
            smtp_user={user}
            smtp_password={password}
            smtp_port=465
            smtp_security=ssl
        '''.format(user=self.master.config.admin_name,
                   password=self.master.config.admin_password))
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)
        configure_ssl(self.master)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\nYour login entry user%d is going" % i)

    def test_EPN_delay_config(self, cleanupmail):
        """Test the smtp_delay configuration option
        """
        epn_conf = textwrap.dedent('''
            [global]
            smtp_delay=A
        ''')
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        result = tasks.ipa_epn(self.master, raiseonerr=False)
        assert "could not convert string to float: 'A'" in result.stderr_text

        epn_conf = textwrap.dedent('''
            [global]
            smtp_delay=-1
        ''')
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)
        result = tasks.ipa_epn(self.master, raiseonerr=False)
        assert "smtp_delay cannot be less than zero" in result.stderr_text
