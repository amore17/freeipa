

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestInstallation(IntegrationTest):
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        pass

    def test_setup(self):
        """
        Test to verify
        """
        tasks.install_master(self.master)
        tasks.install_master(self.replicas[0])
