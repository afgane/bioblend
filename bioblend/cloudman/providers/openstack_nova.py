"""
An implementation of :py:class:`bioblend.cloudman.providers.AbstractCloudProvider`
cloud provider interface using OpenStack's ``nova`` library.
"""

from novaclient.v2 import client
from novaclient import exceptions

import bioblend
from bioblend.cloudman.providers import AbstractCloudProvider

# Uncomment the following line if logging at the prompt is desired
# bioblend.set_stream_logger(__name__)


class NovaCloudProvider(AbstractCloudProvider):
    def __init__(self, config):
        """
        Define the environment in which this instance of CloudMan will be launched.

        :type config: :py:class:`bioblend.util.Bunch` or an object with the
                      required keys
        :param config: Specify account properties for accessing the desired cloud.
                       The following keys are required:
                       - ``name`` - provisionary cloud name;
                       - ``cloud_type`` - cloud type: ``ec2`` or ``openstack``;
                       - ``username`` - OpenStack user username (OS_USERNAME);
                       - ``password`` - OpenStack password (OS_PASSWORD);
                       - ``auth_url`` - Compute API auth (OS_AUTH_URL);
                       - ``tenant_name`` - OpenStack tenant name (OS_TENANT_NAME);
                       - ``tenant_id`` - OpenStack tenant ID (OS_TENANT_ID);
                       - ``region_name`` - OpenStack region name (OS_REGION_NAME);
        """
        super(NovaCloudProvider, self).__init__()
        self.username = config.username
        self.password = config.password
        self.tenant_name = config.tenant_name
        self.auth_url = config.auth_url
        self.region_name = config.region_name
        self.client = client.Client(self.username, self.password,
                                    self.tenant_name, self.auth_url,
                                    self.region_name)

    def create_security_group(self, sg_name="CloudMan"):
        """
        Create a security group with all authorizations required to run CloudMan.

        If the group already exists, check its rules and add the missing ones.

        :type sg_name: str
        :param sg_name: A name for the security group to be created.

        :rtype: dict
        :return: A dictionary containing keys ``name`` (with the value being the
                 name of the security group that was created), ``error``
                 (with the value being the error message if there was an error
                 or ``None`` if no error was encountered), and ``ports``
                 (containing the list of tuples with port ranges that were
                 opened or attempted to be opened).
        """
        # First look if the named security group already exists
        response = {'name': sg_name,
                    'error': None,
                    'ports': self.ports}
        try:
            sg = self.client.security_groups.find(name=sg_name)
        except exceptions.NotFound:
            sg = None
        if not sg:
            sg = self.client.security_groups.create(sg_name, "Security group "
                                                    "for CloudMan")
        # Add rules
        for port in self.ports:
            if not self.rule_exists(sg.rules, from_port=port[0], to_port=port[1]):
                bioblend.log.debug("Adding SG rule %s-%s" % (port[0], port[1]))
                self.client.security_group_rules.create(sg.id, 'tcp', port[0],
                                                        port[1])
        # Add rule that allows communication between instances in the same SG
        group_rule_exists = False
        for rule in sg.rules:
            if rule.get('group').get('name') == sg_name:
                group_rule_exists = True
        if not group_rule_exists:
            self.client.security_group_rules.create(sg.id, ip_protocol='tcp',
                                                    from_port=1, to_port=65535,
                                                    group_id=sg.id)
        return response

    def create_key_pair(self, key_name='cloudman_key_pair'):
        """
        Create a SSH key pair for command line access to the launched instance.

        The key will be created only if a key pair with the provided name does
        not already exist.

        :type sg_name: str
        :param sg_name: A name for the key pair to be created.

        :rtype: dict
        :return: A dictionary containing keys ``name`` (with the value being the
                 name of the key pair that was created), ``error``
                 (with the value being the error message if there was an error
                 or ``None`` if no error was encountered), and ``material``
                 (containing the unencrypted PEM encoded RSA private key if the
                 key was created or ``None`` if the key already eixsted).
        """
        pass

    def get_all_key_pairs(self):
        """
        Get all key pairs associated with your account.

        :rtype: list
        :return: A list of ssh key pairs for this account.
        """
        return self.client.keypairs.list()

    def launch(self, cluster_name, image_id, instance_type, password,
               kernel_id=None, ramdisk_id=None, key_name='cloudman_key_pair',
               security_groups=['CloudMan'], placement='', **kwargs):
        pass

    def find_placements(self, instance_type, cluster_name=None):
        pass

    def get_status(self, instance_id):
        pass
