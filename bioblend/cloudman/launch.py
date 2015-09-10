"""
Setup and launch a CloudMan cluster.
"""
from bioblend.cloudman.providers import ec2_boto
# from bioblend.cloudman.providers import openstack_nova

# Uncomment the following line if no logging from boto is desired
# bioblend.logging.getLogger('boto').setLevel(bioblend.logging.CRITICAL)
# Uncomment the following line if logging at the prompt is desired
# bioblend.set_stream_logger(__name__)


def instance_types(cloud_name='generic'):
    """
    Return a list of dictionaries containing details about the available
    instance types for the given `cloud_name`.

    :type cloud_name: str
    :param cloud_name: A name of the cloud for which the list of instance
                       types will be returned. Valid values are: `aws`,
                       `nectar`, `generic`.

    :rtype: list
    :return: A list of dictionaries describing instance types. Each dict will
             contain the following keys: `name`, `model`, and `description`.
    """
    instance_list = []
    if cloud_name.lower() == 'aws':
        instance_list.append({"model": "c3.large",
                              "name": "Compute optimized Large",
                              "description": "2 vCPU/4GB RAM"})
        instance_list.append({"model": "c3.2xlarge",
                              "name": "Compute optimized 2xLarge",
                              "description": "8 vCPU/15GB RAM"})
        instance_list.append({"model": "c3.8xlarge",
                              "name": "Compute optimized 8xLarge",
                              "description": "32 vCPU/60GB RAM"})
    elif cloud_name.lower() in ['nectar', 'generic']:
        instance_list.append({"model": "m1.small",
                              "name": "Small",
                              "description": "1 vCPU / 4GB RAM"})
        instance_list.append({"model": "m1.medium",
                              "name": "Medium",
                              "description": "2 vCPU / 8GB RAM"})
        instance_list.append({"model": "m1.large",
                              "name": "Large",
                              "description": "4 vCPU / 16GB RAM"})
        instance_list.append({"model": "m1.xlarge",
                              "name": "Extra Large",
                              "description": "8 vCPU / 32GB RAM"})
        instance_list.append({"model": "m1.xxlarge",
                              "name": "Extra-extra Large",
                              "description": "16 vCPU / 64GB RAM"})
    return instance_list


class CloudManLauncher(object):
    def __init__(self, config):
        """
        Define the environment in which this instance of CloudMan will be launched.

        :type config: :py:class:`bioblend.util.Bunch`
        :param config: A configuration object containing cloud connection info.
                       The object must contain user access credentials as well
                       as cloud access info. See the implementation class for
                       the chosen cloud provider for the required field details.
        """
        self.cloud_provider = None
        if config.cloud_type == 'ec2':
            self.cloud_provider = ec2_boto.BotoCloudProvider(config)
        # elif config.cloud_type == 'openstack':
        #     self.cloud_provider = openstack_nova.NovaCloudProvider(config)

    def __repr__(self):
        return "CloudManLauncher for {0}".format(self.config.name)

    def launch(self, cluster_name, image_id, instance_type, password,
               key_name='cloudman_key_pair', security_groups=['CloudMan'],
               placement='', **kwargs):
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
        return self.cloud_provider.launch(cluster_name=cluster_name,
                                          image_id=image_id,
                                          instance_type=instance_type,
                                          password=password,
                                          key_name=key_name,
                                          security_groups=security_groups,
                                          placement=placement,
                                          **kwargs)

    def get_status(self, instance_id):
        """
        Check on the status of an instance.

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
        return self.cloud_provider.get_status(instance_id)

    def get_clusters_pd(self, include_placement=True):
        """
        Return *persistent data* of all existing clusters for this account.

        :type include_placement: bool
        :param include_placement: Whether or not to include region placement for
                                  the clusters. Setting this option will lead
                                  to a longer function runtime.

        :rtype: dict
        :return: A dictionary containing keys ``clusters`` and ``error``. The
                 value of ``clusters`` will be a dictionary with the following keys
                 ``cluster_name``, ``persistent_data``, ``bucket_name`` and optionally
                 ``placement`` or an empty list if no clusters were found or an
                 error was encountered. ``persistent_data`` key value is yet
                 another dictionary containing given cluster's persistent data.
                 The value for the ``error`` key will contain a string with the
                 error message.

        .. versionadded:: 0.3
        .. versionchanged:: 0.7.0
            The return value changed from a list to a dictionary.
        """
        return self.cloud_provider.get_clusters_pd(include_placement)

    def compose_user_data(self, user_provided_data):
        """
        Compose and format the user data required when launching an instance.

        This method will filter the providerd ``user_provided_data`` to
        exclude fields that should not be provided when launching an instance
        as well as make sure all the required fields are included.

        :type user_provided_data: dict
        :param user_provided_data: the raw-formatted user data provided by a
                                   user (or an app) required to identify a cluster.

        :rtype: str
        :return: Formatted user data formatted with one user data value per line.
        """
        return self.cloud_provider.compose_user_data(user_provided_data)

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
        returned as stored in its persistent data.

        :type instance_type: str
        :param instance_type: API name for the instance type

        :type cluster_name: str
        :param cluster_name: An optional name of the cluster whose placement
                             is sought after.

        :rtype: dict
        :return: A dictionary with ``zones`` and ``error`` keywords.

        .. versionchanged:: 0.3
            - Changed method name from ``_find_placements`` to ``find_placements``.
            - Added ``cluster_name`` parameter.

        .. versionchanged:: 0.7.0
            - The return value changed from a list to a dictionary.
            - Removed ``ec2_conn` and ``cloud_type`` parameters.
        """
        return self.cloud_provider.find_placements(instance_type, cluster_name)
