#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#
import uuid
import time
import six

from ipalib import api, errors, DNParam, Flag, _
from ipalib import output, Method, Object
from ipalib.plugable import Registry
from .baseldap import pkey_to_value
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Rebuild Schema Compatibility Tree.
""") + _("""
For different reasons, the compat tree maps might get corrupted and some
entries would be missing.
""") + _("""
The compat-tree-rebuild command can be used to rebuild online the whole compat
tree on demand via a DS task.
""") + _("""
EXAMPLE:
""") + _("""
 Rebuild compat tree:
    ipa compat-tree-rebuild
""")

register = Registry()

REBUILD_TASK_CONTAINER = DN(('cn', 'Schema compatibility refresh task'),
                            ('cn', 'tasks'),
                            ('cn', 'config'))


@register()
class compat_task(Object):
    takes_params = (
        DNParam(
            'dn',
            label=_('Task DN'),
            doc=_('DN of the started task'),
        ),
    )


@register()
class compat_tree_rebuild(Method):
    __doc__ = _('Rebuild Schema Compatibility Tree.')

    obj_name = 'compat_task'
    attr_name = 'rebuild'

    takes_options = (
        Flag(
            'no_wait?',
            default=False,
            label=_('No wait'),
            doc=_("Don't wait for rebuilding schema compatibility tree"),
        ),
    )
    has_output = output.standard_entry

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        cn = str(uuid.uuid4())

        task_dn = DN(('cn', cn), REBUILD_TASK_CONTAINER)

        entry = ldap.make_entry(
            task_dn,
            objectclass=['top', 'extensibleObject'],
            cn=[cn],
            basedn=[api.env.basedn],
            scope=['sub'],
            ttl=[3600])
        ldap.add_entry(entry)

        summary = _('Schema compatibility tree rebuild task started')
        result = {'dn': task_dn}

        if not options.get('no_wait'):
            summary = _('Schema compatibility tree rebuild task completed')
            result = {}
            start_time = time.time()

            while True:
                try:
                    task = ldap.get_entry(task_dn)
                except errors.NotFound:
                    break

                if 'nstaskexitcode' in task:
                    if str(task.single_value['nstaskexitcode']) == '0':
                        summary=task.single_value['nstaskstatus']
                        break
                    raise errors.DatabaseError(
                        desc=task.single_value['nstaskstatus'],
                        info=_("Task DN = '%s'" % task_dn))
                time.sleep(1)
                if time.time() > (start_time + 60):
                   raise errors.TaskTimeout(task=_('Compat'), task_dn=task_dn)

        return dict(
            result=result,
            summary=unicode(summary),
            value=pkey_to_value(None, options))
