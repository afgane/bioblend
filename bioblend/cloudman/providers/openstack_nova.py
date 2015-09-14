"""
An implementation of :py:class:`bioblend.cloudman.providers.AbstractCloudProvider`
cloud provider interface using OpenStack's ``nova`` library.
"""
import yaml
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
        self.config = config
        self.cloud = config  # Until refs to this field get removed from ec2 impl
        self.cloud_name = config.name
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
        response = {'name': sg_name,
                    'error': None,
                    'ports': self.ports}
        # Check if the security group (SG) already exists
        try:
            sg = self.client.security_groups.find(name=sg_name)
        except exceptions.NotFound:
            sg = None
        # If the SG doesn't exist, create it
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

        :type key_name: str
        :param key_name: A name for the key pair to be created.

        :rtype: dict
        :return: A dictionary containing keys ``name`` (with the value being the
                 name of the key pair that was created), ``error``
                 (with the value being the error message if there was an error
                 or ``None`` if no error was encountered), and ``material``
                 (containing the unencrypted PEM encoded RSA private key if the
                 key was created or ``None`` if the key already eixsted).
        """
        response = {'name': key_name,
                    'material': None,
                    'error': None}
        # Check if the key pair (KP) under the given name already exists.
        try:
            kp = self.client.keypairs.find(name=key_name)
        except exceptions.NotFound:
            kp = None
        # If the KP doesn't exist, create it
        if not kp:
            kp = self.client.keypairs.create(name=key_name)
            response['material'] = kp.private_key
            bioblend.log.info("Created key pair '%s'" % kp.name)
        return response

    def get_all_key_pairs(self):
        """
        Get all key pairs associated with your account.

        :rtype: list
        :return: A list of ssh key pairs for this account.
        """
        return self.client.keypairs.list()

    def launch(self, cluster_name, image_id, instance_type, password,
               key_name='cloudman_key_pair', security_groups=['CloudMan'],
               placement='', **kwargs):
        """
        Start a new cluster with the given parameters.

        In addition to the arguments from the method signature, additional
        ``kwargs`` parameters can be specified that correspond to CloudMan's
        user data, see `<http://wiki.g2.bx.psu.edu/CloudMan/UserData>`_

        :type cluster_name: str
        :param cluster_name: A name of a CloudMan cluster. This can be a name
                             for a new cluster or from a saved cluster.

        :type image_id: str
        :param image_id: Image identifier.

        :type instance_type: str
        :param instance_type: API name of the instance type (e.g., m1.large).

        :type password: str
        :param password: A plain text password to be used for accessing
                         CloudMan and the rest of the cluster.

        :type key_name: str
        :param key_name: SSH key pair name.

        :type security_groups: list
        :param security_groups: A list of strings specifying security group
                                names with which the cluster should be launched.

        :type placement: str
        :param placement: Cloud zone/region identifier where to launch the
                          cluster.

        :rtype: dict
        :return: The properties and info with which an instance was launched:
                - ``sg_names`` - names of the security groups;
                - ``kp_name`` - name of the key pair;
                - ``kp_material`` - the private portion of the key pair
                  (*note* that this portion of the key pair is available
                  and can be retrieved *only* at the time the key is created,
                  which will happen only if no key with the name provided in
                  the ``key_name`` argument exists);
                - ``instance_id`` - instance ID of the started instance;
                - ``error`` - an error message, if there was one
                - ``rs`` - always ``None``
        """
        response = {'sg_names': [],
                    'kp_name': '',
                    'kp_material': '',
                    'instance_id': '',
                    'error': None,
                    'rs': None}
        # Satisfy the prerequisites first
        for sg in security_groups:
            cmsg = self.create_security_group(sg)
            response['sg_names'].append(cmsg['name'])
            response['error'] = cmsg['error']
            if response['error']:
                return response
        kp = self.create_key_pair(key_name)
        response['kp_name'] = kp['name']
        response['kp_material'] = kp['material']
        response['error'] = kp['error']
        if response['error']:
            return response
        # TODO: find placement, particularly for existing clusters
        placement = None
        kwargs['cluster_name'] = cluster_name
        kwargs['cloud_name'] = self.cloud_name
        kwargs['password'] = password
        ud = self.compose_user_data(kwargs)
        try:
            image = self.client.images.find(id=image_id)
            os_flavor = self.client.flavors.find(name=instance_type)
            # nic = self.client.networks.find(label='Web')
        except exceptions.NoUniqueMatch, exc:
            response['error'] = ("Cannot find image ID {0} or type {1}: {2}"
                                 .format(image_id, instance_type, exc))
            bioblend.log.error(response['error'])
            return response
        name = "Master: {0}".format(cluster_name)
        instance = self.client.servers.create(flavor=os_flavor, image=image,
                                              name=name, key_name=kp['name'],
                                              security_groups=response['sg_names'],
                                              availability_zone=placement,
                                              userdata=ud)  # , nics=[{'net-id': nic.id}])
        response['instance_id'] = instance.id
        return response

    def _get_cloud_info(self, cloud, as_str=False):
        """
        Return cloud connection properties used by this object.

        :type as_str: bool
        :param as_str: If set, the method returns a `str` else return a ``dict``.

        :rtype: dict or str
        :return: Get all the cloud-connection parameters used in this object
                 and return them as a dict or a string with on key-value per
                 line.
        """
        ci = {}
        ci['cloud_type'] = self.config.cloud_type
        ci['os_username'] = self.username
        ci['os_password'] = self.password
        ci['os_tenant_name'] = self.tenant_name
        ci['os_auth_url'] = self.auth_url
        ci['os_region_name'] = self.region_name
        if as_str:
            ci = yaml.dump(ci, default_flow_style=False, allow_unicode=False)
        return ci

    def find_placements(self, instance_type, cluster_name=None):
        """
        Find a list of placement zones that support the specified instance type.

        :type instance_type: str
        :param instance_type: API name of the instance type (e.g., m1.large)

        :type cluster_name: str
        :param cluster_name: A name of a CloudMan cluster whose placement to
                             search for.

        :rtype: dict
        :return: A dictionary with ``zones`` and ``error`` keywords.
        """
        pass

    def get_status(self, instance_id):
        """
        Get the status of an instance.

        :type instance_id: str
        :param instance_id: Instance identifier

        :rtype: dict
        :return: Instance status, captured via the the following keys:
            - ``instance_state`` - expected values are: ``pending``,
                                   ``booting``, ``running``, or ``error`` and
                                   represent the state of the underlying instance;
            - ``public_ip`` - instance public IP address;
            - ``placement`` - zone where the instance was launched;
            - ``error`` - an error message if an error was encountered.
        """
        response = {'instance_state': "",
                    'public_ip': "",
                    'placement': "",
                    'error': ""}
        try:
            instance = self.client.servers.get(instance_id)
        except exceptions.NoUniqueMatch, exc:
            response['error'] = ("Cannot find instance with ID {0}: {1}"
                                 .format(instance_id, exc))
            bioblend.log.error(response['error'])
            return response
        response['placement'] = getattr(instance, 'OS-EXT-AZ:availability_zone')
        # TODO figure out how to get the IP for clouds where network interfaces
        # are used vs. public IPs for each instance
        public_ip = instance.accessIPv4
        response['public_ip'] = public_ip

        # Map OS state names to internal ones
        state = instance.status
        if state == 'BUILD':
            state = 'pending'
        elif state == 'ACTIVE':
            cm_url = "http://{dns}/cloud".format(dns=public_ip)
            # Wait until the CloudMan URL is accessible to return the data
            if self._checkURL(cm_url) is True:
                state = 'running'
            else:
                state = 'booting'
            state = 'running'
        elif state == 'ERROR':
            state = 'error'
            response['error'] = instance.fault.get('message')
        response['instance_state'] = state
        return response
