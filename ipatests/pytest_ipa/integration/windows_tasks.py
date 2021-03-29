import re
import logging
import subprocess
from collections import namedtuple

import winrm

from ipatests.util import wait_for


WinRMCommandResult = namedtuple('WinRMCommandResult',
                                'returncode stdout_text stderr_text exception')


def winrm_run_command(host, argv, raiseonerr=True):
    session = winrm.Session(host.external_hostname,
                            (host.ssh_username, host.ssh_password))
    if isinstance(argv, str):
        cmd = argv
        args = ()
    else:
        # TODO: escape doublequote in arguments
        args = ['"%s"' % s for s in argv[1:]]
        cmd = argv[0]
    logging.info('WINRM RUN_CMD host: %s, cmd: %s, args: %s',
                 host.external_hostname, cmd, args)
    result = session.run_cmd(cmd, args)
    stdout_text = result.std_out.decode('utf-8')
    stderr_text = result.std_err.decode('utf-8')
    exception = subprocess.CalledProcessError(
        result.status_code, argv, stdout_text, stderr_text)
    if raiseonerr and result.status_code != 0:
        logging.error('result code: %s, stderr: %s', result.status_code,
                      result.std_err)
        raise exception
    return WinRMCommandResult(result.status_code, stdout_text, stderr_text,
                              exception)


def winrm_run_powershell_script(host, script, raiseonerr=True):
    return winrm_run_command(host, ['powershell', '-c', script],
                             raiseonerr=raiseonerr)


def reboot(host):
    def get_system_start_time():
        script = '(Get-WmiObject -ClassName Win32_OperatingSystem)'\
                 '.LastBootUpTime'
        return winrm_run_powershell_script(host, script).stdout_text

    initial_system_start_time = get_system_start_time()
    winrm_run_command(host, 'shutdown /r /t 0')

    def check_start_time_changed():
        try:
            system_start_time = get_system_start_time()
            return (system_start_time != initial_system_start_time and
                    re.match(r'^\d+\.\d+\+000\s*$', system_start_time))
        except Exception as e:
            logging.debug('Error getting start time %s', e)
            return False

    if not wait_for(check_start_time_changed, 300):
        raise Exception('Windows host failed to start up')


def registry_add(host, path, key, value, value_type):
    winrm_run_command(host, [
        'reg', 'add', path, '/v', key, '/d', value, '/t', value_type, '/f'])


def registry_delete(host, path, key, ignore_missing=False):
    res = winrm_run_command(host, ['reg', 'delete', path, '/v', key, '/f'],
                            raiseonerr=not ignore_missing)
    if res.returncode != 0:
        if not (ignore_missing and res.returncode == 1 and
                'unable to find the specified registry key' in res.stderr_text):
            raise res.exception


def set_autologon(host, login, password):
    path = r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    registry_add(host, path, 'DefaultUserName', login, 'REG_SZ')
    registry_add(host, path, 'DefaultPassword', password, 'REG_SZ')
    registry_add(host, path, 'AutoAdminLogon', '1', 'REG_SZ')


def add_user_to_local_group(host, user, group):
    winrm_run_command(host, ['net', 'localgroup', group, user, '/add'])


def remove_user_from_local_group(host, user, group):
    winrm_run_command(host, ['net', 'localgroup', group, user, '/delete'])

def add_user_to_domain_group(host, user, group):
    winrm_run_command(host, ['net', 'group', group, user, '/add'])


def remove_user_from_domain_group(host, user, group):
    winrm_run_command(host, ['net', 'group', group, user, '/delete'])
