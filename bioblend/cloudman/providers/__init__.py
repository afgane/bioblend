"""
A cloud provider abstract interface.
"""
from six import with_metaclass
from abc import ABCMeta, abstractmethod
import logging
logging.captureWarnings(True)

# Uncomment the following lines if logging at the prompt is desired
# import bioblend
# bioblend.set_stream_logger(__name__)


class AbstractCloudProvider(with_metaclass(ABCMeta)):

    @abstractmethod
    def __init__(self, **kwargs):
        """
        Connection properties for a cloud provider (see specific implementaions).
        """
        self.ports = ((20, 21),  # FTP
                      (22, 22),  # SSH
                      (80, 80),  # Web UI
                      (443, 443),  # SSL Web UI
                      (8800, 8800),  # NodeJS Proxy for Galaxy IPython IE
                      # (9600, 9700),  # HTCondor
                      (30000, 30100))  # FTP transfer

    @abstractmethod
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
        pass

    @abstractmethod
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

    @abstractmethod
    def get_all_key_pairs(self):
        """
        Get all key pairs associated with your account.

        :rtype: list
        :return: A list of ssh key pairs for this account.
        """
        pass

    @abstractmethod
    def launch(self, cluster_name, image_id, instance_type, password,
               kernel_id=None, ramdisk_id=None, key_name='cloudman_key_pair',
               security_groups=['CloudMan'], placement='', **kwargs):
        """
        Start a new cluster with the given parameters.

        In addition to the arguments from the method signature, additional
        ``kwargs`` parameters can be specified that correspond to CloudMan's
        user data, see `<http://wiki.g2.bx.psu.edu/CloudMan/UserData>`_

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
                - ``rs`` - `boto <https://github.com/boto/boto/>`_ ``ResultSet``
                  object (available only for Amazon cloud)
        """
        pass

    @abstractmethod
    def find_placements(self, instance_type, cluster_name=None):
        """
        Find a list of placement zones that support the specified instance type.

        If ``cluster_name`` is given and a cluster with the given name exist,
        return a list with only one entry where the given cluster lives.

        Searching for available zones for a given instance type is done by
        checking the spot prices in the potential availability zones for
        support before deciding on a region:
        http://blog.piefox.com/2011/07/ec2-availability-zones-and-instance.html

        Note that, currently, instance-type based zone selection applies only to
        AWS. For other clouds, all the available zones are returned (unless a
        cluster is being recreated, in which case the cluster's placement zone is
        returned sa stored in its persistent data.

        :rtype: dict
        :return: A dictionary with ``zones`` and ``error`` keywords.
        """
        pass

    @abstractmethod
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
        pass

    def rule_exists(self, rules, from_port, to_port, ip_protocol='tcp'):
        """
        A convenience method to check if an authorization rule in a security group
        already exists.
        """
        for rule in rules:
            if (rule.get('ip_protocol') == ip_protocol and
               int(rule.get('from_port', 0)) == from_port and
               int(rule.get('to_port', 0)) == to_port):
                return True
        return False
