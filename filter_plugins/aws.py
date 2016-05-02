import boto3
import boto.vpc
import boto.ec2
import boto.ec2.autoscale

from ansible import errors

def get_sg_cidrs(name, vpc_id, region):
    """Retrieve the CIDR Blocks associated with a Security Group within VPC
    Args:
        name (str): The name of the security group you are looking for.
        vpc_id (str): The VPC id where this security group resides.
        region (str): The region in which the security group resides.

    Basic Usage:
        >>> name = 'web_app'
        >>> region = 'us-west-2'
        >>> vpc_id = 'vpc-123456'
        >>> cidrs = get_sg_cidrs(name, vpc_id, region)
        >>> print cidrs
        ['10.100.0.0/24', '10.100.2.0/24', '10.100.1.0/24']

    Returns:
        List
    """
    client = boto3.client('ec2', region_name=region)
    params = {
        "Filters": [
            {
                "Name": "tag-key",
                "Values": ["Name"]
            },
            {
                "Name": "tag-value",
                "Values": [name]
            },
            {
                "Name": "vpc-id",
                "Values": [vpc_id],
            }
        ]
    }
    sg_groups = client.describe_security_groups(**params)['SecurityGroups']
    if len(sg_groups) == 1:
        cidrs = map(lambda x: x['CidrIp'], sg_groups[0]['IpPermissions'][0]['IpRanges'])
        return cidrs
    elif len(sg_groups) > 1:
        raise errors.AnsibleFilterError(
            "Too many results for {0}: {1}".format(
                name, ",".join(sg_groups)
            )
        )
    else:
        raise errors.AnsibleFilterError(
            "Security Group {0} was not found".format(name)
        )

def get_sg(name, vpc_id, region):
    """Retrieve the Security Group Id from the name and vpc_id
    Args:
        name (str): The name of the security group you are looking for.
        vpc_id (str): The VPC id where this security group resides.
        region (str): The region in which the security group resides.

    Basic Usage:
        >>> name = 'ProductionELB'
        >>> region = 'us-west-2'
        >>> vpc_id = 'vpc-cf548aaa'
        >>> security_group_id = get_sg(name, vpc_id, region)
        >>> print security_group_id
        sg-123456

    Returns:
        String
    """
    connect = boto.ec2.connect_to_region(region)
    filter_by = {
        "tag-key": "Name",
        "tag-value": name,
        "vpc-id": vpc_id
    }
    sg_groups = connect.get_all_security_groups(filters=filter_by)
    if len(sg_groups) == 1:
        return sg_groups[0].id
    elif len(sg_groups) > 1:
        raise errors.AnsibleFilterError(
            "Too many results for {0}: {1}".format(
                name, ",".join(sg_groups)
            )
        )
    else:
        raise errors.AnsibleFilterError(
            "Security Group {0} was not found".format(name)
        )

def get_server_certificate(name, region=None):
    """Retrieve the ARN of the Server Certificate.
    Args:
        name (str): The name of the Server Certificate you are looking for.

    Kwargs:
        region (str): The region in which the Server Certificate resides.

    Basic Usage:
        >>> name = 'start_webapp_com_expires_20160101'
        >>> region = 'us-west-2'
        >>> arn = get_server_certificate(name, region)
        >>> print arn
        'arn:aws:iam::1234567891234:server-certificate/start_webapp_com_expires_20160101'

    Returns:
        String
    """
    client = boto3.client('iam', region_name=region)
    try:
        cert_meta = (
            client.get_server_certificate(
                ServerCertificateName=name
            )['ServerCertificate']['ServerCertificateMetadata']
        )
        return_key = cert_meta['Arn']
    except Exception:
        raise errors.AnsibleFilterError(
            "Server Certificate {0} was not found".format(name)
        )

    return return_key

def get_instance_profile(name, region=None):
    """Retrieve the ARN of the Instance Profile of a IAM Role.
    Args:
        name (str): The name of the IAM role you are looking for.

    Kwargs:
        region (str): The region in which the IAM Role resides.

    Basic Usage:
        >>> name = 'webapp-develop'
        >>> region = 'us-west-2'
        >>> arn = get_instance_profile(name, region)
        >>> print arn
        'arn:aws:iam::1234567891234:instance-profile/webapp-develop'

    Returns:
        String
    """
    client = boto3.client('iam', region_name=region)
    try:
        profile = (
            client.get_instance_profile(
                InstanceProfileName=name
            )['InstanceProfile']
        )
        return_key = profile['Arn']
    except Exception:
        raise errors.AnsibleFilterError(
            "IAM instance profile {0} was not found".format(name)
        )

    return return_key

def get_sqs(name, key='arn', region=None):
    """Retrieve the ARN or URL of the SQS queue.
    Args:
        name (str): The name of the queue you are looking for.

    Kwargs:
        key (str): This can be arn or url.
            default=arn
        region (str): The region in which the SQS Queue resides.

    Basic Usage:
        >>> name = 'webapp-develop'
        >>> region = 'us-west-2'
        >>> arn = get_instance_profile(name, region)
        >>> print arn
        'arn:aws:sqs:us-west-2:1234567891234:webapp-develop'

    Returns:
        String
    """
    client = boto3.client('sqs', region_name=region)
    try:
        url = client.get_queue_url(QueueName=name)['QueueUrl']
        if key == 'arn':
            attributes = (
                client.get_queue_attributes(
                    QueueUrl=url, AttributeNames=['QueueArn']
                )['Attributes']
            )
            return_key = attributes['QueueArn']
        else:
            return_key = url
    except Exception:
        raise errors.AnsibleFilterError(
            "SQS Queue {0} was not found".format(name)
        )

    return return_key

def get_dynamodb_base_arn(region=None):
    """Retrieve the base ARN of the AWS acccount you are in.
    Args:
        name (str): The name of the DyanamoDB you are looking for.

    Kwargs:
        key (str): This can be arn or url.
            default=arn
        region (str): The region in which the DynamoDB resides.

    Basic Usage:
        >>> region = 'us-west-2'
        >>> arn = get_dynamodb_base_arn(region)
        >>> print arn
        'arn:aws:dynamodb:us-west-2:1234567891234:table'

    Returns:
        String
    """
    client = boto3.client('dynamodb', region_name=region)
    try:
        tables = client.list_tables(Limit=1)
        table = tables['TableNames'][0]
        arn = client.describe_table(TableName=table)['Table']['TableArn']
        base_arn = arn.split('/')[:-1]
        return base_arn[0]
    except Exception:
        raise errors.AnsibleFilterError(
            "Unable to find 1 DynamoDB Table"
        )

def get_kinesis_stream_arn(stream_name, region=None):
    """Retrieve the ARN of the Kinesis Stream.
    Args:
        name (str): The name of the stream you are looking for.

    Kwargs:
        region (str): The region in which the Kinesis Stream resides.

    Basic Usage:
        >>> stream_name = 'test-stream'
        >>> region = 'us-west-2'
        >>> arn = get_kinesis_stream_arn(stream_name, region)
        >>> print arn
        'arn:aws:kinesis:us-west-2:1234567891234:stream/test-stream'

    Returns:
        String
    """
    client = boto3.client('kinesis', region_name=region)
    try:
        arn = (
            client.describe_stream(
                StreamName=stream_name, Limit=1
            )['StreamDescription']['StreamARN']
        )
        return arn
    except Exception:
        raise errors.AnsibleFilterError(
            "Unable to find Kinesis Stream {0}".format(stream_name)
        )

def zones(region=None):
    """Retrieve all of the zones in a region.
    Kwargs:
        region (str): The region in which the Zones resides.

    Basic Usage:
        >>> zones_in_region = zones('us-west-2')
        >>> print zones_in_region
        ['us-west-2a', 'us-west-2b', 'us-west-2c']

    Returns:
        List
    """
    client = boto3.client('ec2', region_name=region)
    zone_names = (
        map(lambda x: x['ZoneName'],
            client.describe_availability_zones()['AvailabilityZones']
            )
    )
    zone_names.sort()
    return zone_names

def get_all_vpcs_info_except(except_ids, region=None):
    """Retrieve all VPC's except for a list of ids.
    Args:
        except_ids (list): List of vpc ids, that you do not want to match against.

    Basic Usage:
        >>> vpc_ids = ['vpc-1234567']
        >>> get_all_vpcs_info_except(vpc_ids)
        ['vpc-68548239', 'vpc-7654321']

    Returns:
        List
    """
    vpcs_info = list()
    client = boto3.client('ec2', region_name=region)
    params = {
        'Filters': [
            {
                'Name': 'state',
                'Values': ['available'],
            },
            {
                'Name': 'isDefault',
                'Values': ['false'],
            }
        ]
    }
    vpcs = client.describe_vpcs(**params)
    if vpcs:
        for vpc_id in except_ids:
            for vpc in vpcs['Vpcs']:
                if vpc_id != vpc['VpcId']:
                    name = ''
                    if vpc.get('Tags', None):
                        for tag in vpc['Tags']:
                            if tag.get('Key', None) == 'Name':
                                name = tag.get('Value')


                    vpcs_info.append(
                        {
                            'name': name,
                            'id': vpc['VpcId'],
                            'cidr': vpc['CidrBlock'],
                        }
                    )
    if vpcs_info:
        return vpcs_info
    else:
        raise errors.AnsibleFilterError("No vpcs were found")

def get_rds_address(instance_name, region=None):
    """Retrieve RDS Endpoint Address.
    Args:
        instance_name (str): The rds instance name.

    Kwargs:
        region (str): Aws region

    Basic Usage:
        >>> instance_name = 'db-dev'
        >>> address = get_rds_address(instance_name)
        >>> print address
        'db-dev.lkjhkjdfd.us-west-2.rds.amazonaws.com'

    Returns:
        String
    """
    client = boto3.client('rds', region_name=region)
    try:
        rds_instances = (
            client.describe_db_instances(
                DBInstanceIdentifier=instance_name
            )['DBInstances']
        )
        if len(rds_instances) == 1:
            return rds_instances[0]['Endpoint']['Address']
        else:
            raise errors.AnsibleFilterError("More than rds 1 instance found")
    except Exception as e:
        raise errors.AnsibleFilterError(
            "DBInstance {0} not found".format(instance_name)
        )

def get_route_table_ids(vpc_id, region=None):
    """Retrieve a list of route table ids in a VPC.
    Args:
        vpc_id (str): The vpc id in which the route tables you are looking
            for lives in.

    Kwargs:
        region (str): Aws region

    Basic Usage:
        >>> vpc_id = 'vpc-12345678'
        >>> get_route_table_ids(vpc_id, 'us-west-2')
        ['rtb-1234567a']

    Returns:
        List
    """
    route_ids = list()
    client = boto3.client('ec2', region_name=region)
    params = {
        'Filters': [
            {
                'Name': 'vpc-id',
                'Values': [vpc_id],
            },
            {
                'Name': 'association.main',
                'Values': ['false']
            }
        ]
    }
    routes = client.describe_route_tables(**params)
    if routes:
        route_ids = (
            map(lambda route: route['RouteTableId'], routes['RouteTables'])
        )
        return route_ids
    else:
        raise errors.AnsibleFilterError("No routes were found")

def get_all_route_table_ids(region):
    """Retreive all route tables for a region
    Args:
        region (str): Aws region

    Basic Usage:
        >>> get_all_route_table_ids("us-west-2")
        ['rtb-1234567']

    Returns:
        List
    """
    route_ids = list()
    client = boto3.client('ec2', region_name=region)
    params = {
        'Filters': [
            {
                'Name': 'association.main',
                'Values': ['false']
            }
        ]
    }
    routes = client.describe_route_tables(**params)
    if routes:
        for route in routes['RouteTables']:
            route_ids.append(route['RouteTableId'])
        return route_ids
    else:
        raise errors.AnsibleFilterError("No routes were found")

def get_all_route_table_ids_except(vpc_id, region=None):
    """Retrieve all route tables for all VPC's except for vpc_id.
    Args:
        vpc_id (str): The vpc you want to exclude routes from.

    Kwargs:
        region (str): Aws region.

    Basic Usage:
        >>> vpc_id = 'vpc-1234567'
        >>> get_all_route_table_ids_except(vpc_id)
        ['rtb-5f78343a']

    Returns:
        List
    """
    route_ids = list()
    client = boto3.client('ec2', region_name=region)
    params = {
        'Filters': [
            {
                'Name': 'association.main',
                'Values': ['false']
            }
        ]
    }
    routes = client.describe_route_tables(**params)
    if routes:
        for route in routes['RouteTables']:
            if route['VpcId'] != vpc_id:
                route_ids.append(route['RouteTableId'])
        if len(route_ids) > 0:
            return route_ids
        else:
            raise errors.AnsibleFilterError("No routes were found")
    else:
        raise errors.AnsibleFilterError("No routes were found")

def get_subnet_ids_in_zone(vpc_id, zone, region=None):
    """Retrieve subnet ids in a zone for VPC.
    Args:
        vpc_id (str): The vpc id in which the subnet you are looking
            for lives in,
        zone (str): The region in which the subnet resides.

    Basic Usage:
        >>> cidrs = ['10.100.10.0/24', '10.100.12.0/24', '10.100.11.0/24']
        >>> vpc_id = 'vpc-1234567'
        >>> aws_region = 'us-west-2'
        >>> subnet_ids = get_subnet_ids(vpc_id, cidrs, aws_region)
        >>> print subnet_ids
        [u'subnet-1234567a', u'subnet-9876543b', u'subnet-5436789c']

    Returns:
        List
    """
    subnet_ids = list()
    client = boto3.client('ec2', region_name=None)
    params = {
        'Filters': [
            {
                'Name': 'vpc-id',
                'Values': [vpc_id],
            },
            {
                'Name': 'availabilityZone',
                'Values': [zone],
            }
        ]
    }
    subnets = client.describe_subnets(**params)
    if subnets:
        subnet_ids = map(lambda subnet: subnet.id, subnets)
        return subnet_ids
    else:
        raise errors.AnsibleFilterError("No subnets were found")

def get_subnet_ids(vpc_id, cidrs, region=None):
    """Retrieve a list of subnet ids, that correlate to the CIDR blocks passed.
    Args:
        vpc_id (str): The vpc id in which the subnet you are looking
            for lives in,
        cidrs (list): The list of cidrs that you are performing the search on.

    Kwargs:
        region (str): The region in which the subnet resides.

    Basic Usage:
        >>> cidrs = ['10.100.10.0/24', '10.100.12.0/24', '10.100.11.0/24']
        >>> vpc_id = 'vpc-1234567'
        >>> aws_region = 'us-west-2'
        >>> subnet_ids = get_subnet_ids(vpc_id, cidrs, aws_region)
        >>> print subnet_ids
        [u'subnet-4c2f683b', u'subnet-877de3de', u'subnet-441e3f21']

    Returns:
        List
    """
    subnet_ids = list()
    client = boto3.client('ec2', region_name=None)
    params = {
        'Filters': [
            {
                'Name': 'vpc-id',
                'Values': [vpc_id],
            },
            {
                'Name': 'cidrBlock',
                'Values': cidrs,
            }
        ]
    }
    subnets = (
        sorted(
            client.describe_subnets(**params)['Subnets'],
            key=lambda subnet: subnet['AvailabilityZone']
        )
    )
    if subnets:
        subnet_ids = map(lambda subnet: subnet['SubnetId'], subnets)
        return subnet_ids
    else:
        raise errors.AnsibleFilterError("No subnets were found")

def get_vpc_id_by_name(name, region):
    """Retrieve the VPC id by the name of the VPC
    Args:
        name (str): The name of the vpc you are retrieving the id for.
        region (str): The region in which the elb resides.

    Basic Usage:
        >>> vpc_name = 'test'
        >>> aws_region = 'us-west-2'
        >>> vpc_id = get_vpc_id_by_name(vpc_name, aws_region)
        >>> print vpc_id
        'vpc-1234567'

    Returns:
        String
    """
    connect = boto.vpc.connect_to_region(region)
    vpcs_in_region = connect.get_all_vpcs()
    for vpc in vpcs_in_region:
        if vpc.tags.has_key("Name"):
            if vpc.tags["Name"] == name:
                return vpc.id

    raise errors.AnsibleFilterError(
        "VPC ID for VPC name {0} was not found in region {1}"
        .format(name, region)
    )

def vpc_exists(name, region):
    """Return a VPC ID if a VPC is found by name, else return does not exist.
    Args:
        name (str): The name of the vpc you are retrieving the id for.
        region (str): The region in which the VPC resides.

    Basic Usage:
        >>> vpc_name = 'test'
        >>> aws_region = 'us-west-2'
        >>> vpc_id = vpc_exists(vpc_name, aws_region)
        'vpc-1234567'

    Returns:
        String
    """
    vpc_id = None
    try:
        vpc_id = get_vpc_id_by_name(name, region)
    except Exception:
        vpc_id = 'does not exist'
    return vpc_id

def get_ami_images(name, region, arch="x86_64", virt_type="hvm",
                 owner="099720109477", sort=False, sort_by="creationDate",
                 sort_by_tag=False, tags=None, order="desc"):
    """
    Args:
        name (str): The name of the of the image you are searching for.
        region (str): The region in which the image resides.
    Kwargs:
        arch (str): The architecture of the image (i386|x86_64)
            default=x86_64
        virt_type (str): (hvm|pv)
        owner (str): The owner of the image (me|amazon|099720109477) etc...
            default=099720109477 (This is Canonical)
        sort (bool): If you know the search is going to return multiple images,
            than you can sort based on an attribute of the ami image you are
            looking for. default=False
        sort_by (str): The instance attribute or tag key you want to sort on.
        sort_by_tag (bool): In order to sort by tag, this arguments needs
            to be flagged as True. default=False
        tags (list of tuples): Filter base on multiple tags.
            example.. tags=[(State, current)]
            default=None
        order (str): asc or desc. default=desc

    Basic Usage:
        >>> name = 'ubuntu/images/hvm/ubuntu-trusty-14.04-amd64-server-20150609'
        >>> aws_region = 'us-west-2'
        >>> images = get_ami_images(name, aws_region)
        [Image:ami-a9e2da99]

    Returns:
        List
    """
    reverse = False
    filter_by = {}
    if isinstance(tags, list):
        for key, val in tags:
            key = "tag:{0}".format(key)
            filter_by[key] = val

    filter_by.update(
        {
            "name": name,
            "architecture": arch,
            "virtualization_type": virt_type
        }
    )
    if order == "desc":
        reverse = True

    connect = boto.ec2.connect_to_region(region)
    images = connect.get_all_images(owners=owner, filters=filter_by)
    if images:
        if sort:
            if sort_by_tag:
                images.sort(key=lambda x: x.tags[sort_by], reverse=reverse)
            else:
                images.sort(key=lambda x: getattr(x, sort_by), reverse=reverse)
        return images
    else:
        raise errors.AnsibleFilterError(
            "No images were found with name {0}, arch {1}, and virt_type {2}"
            .format(name, arch, virt_type)
        )

def get_instance(name, region, return_key="ip_address", state=None):
    """Retrieve a property from an ec2 instance.
    Args:
        name (str): The name of the instance id you are retrieving the key for.
        region (str): The region in which the elb resides.

    Kwargs:
        return_key (str): the property of the instance you want to return.
            default=ip_address
        state (str): A valid instance state to add to the search filter.
            The following are valid states: pending, running, stopped,
            stopping, rebooting, shutting-down, terminated.
            default=None

    Basic Usage:
        >>> name = 'base'
        >>> region = 'us-west-2'
        >>> ip_address = get_instance(name, region)
        u'10.0.0.101'

    Returns:
        String
    """
    filter_by = {
        "tag:Name": name,
    }
    if state:
        filter_by["instance-state-name"] = state
    connect = boto.ec2.connect_to_region(region)
    images = connect.get_all_instances(filters=filter_by)
    if len(images) == 1:
        instance = images[0].instances[0]
        result = getattr(instance, return_key)
        return result
    elif len(images) > 1:
        raise errors.AnsibleFilterError(
            "More than 1 instance was found with name {0} in region {1}"
            .format(name, region)
        )
    elif len(images) == 0:
        raise errors.AnsibleFilterError(
            "No instance was found with name {0} in region {1}"
            .format(name, region)
        )

def get_older_images(name, region, exclude_ami=None,
                     exclude_archived=True, **kwargs):
    """Retrieve a list of AMI images. You can exclude an AMI image from this list,
       or exclude images that have the tag ArchiveDate.
    Args:
        name (str): The name of the instance id you are retrieving the key for.
        region (str): The region in which the elb resides.

    Kwargs:
        exclude_ami (str): The ami_image you would like to exclude from
            this search. default=None
        exclude_archived (bool): Do not include images that are already
            tagged with ArchiveDate. default=True

    Basic Usage:
        >>> ami_name = 'base-*'
        >>> images = get_older_images(base, 'us-west-2')
        >>> print images
        [u'ami-1234567']

    Returns:
        List
    """
    owner = "self"
    images = get_ami_images(name, region, owner=owner, **kwargs)
    image_ids = []
    amis_that_are_already_tagged = []
    if images:
        if exclude_archived:
            for ami in images:
                if ami.tags.has_key('ArchivedDate'):
                    amis_that_are_already_tagged.append(ami.id)
        image_ids = map(lambda image: image.id, images)
        if exclude_ami in image_ids:
            image_ids.remove(exclude_ami)
        return list(set(image_ids).difference(amis_that_are_already_tagged))
    else:
        raise errors.AnsibleFilterError(
            "No instance was found with name {0} in region {1}"
            .format(name, region)
        )

def latest_ami_id(name, region):
    """Retrieve the latest AMI ID sorted by creationDate.
    Args:
        name (str): The name of the ami image you are searching for.
        region (str): The region in which the AMI resides.

    Basic Usage:
        >>> name = 'base-*'
        >>> image_id = latest_ami_id(base, 'us-west-2')
        >>> print image_id
        u'ami-1234567'

    Returns:
        String
    """
    images = (
        get_older_images(
            name, region, sort=True, sort_by='creationDate',
            order='desc'
        )
    )
    return images[0]

def get_ami_image_id(name, region, **kwargs):
    """Retrieve an AMI ID by the name of the image. Default owner is canonical
    Args:
        name (str): The name of the of the image you are searching for.
        region (str): The region in which the image resides.

    Basic Usage:
        >>> name = 'ubuntu/images/hvm/ubuntu-trusty-14.04-amd64-server-20150609'
        >>> aws_region = 'us-west-2'
        >>> get_ami_image_id(name, aws_region)
        u'ami-1234567'

    Returns:
        String
    """
    images = get_ami_images(name, region, **kwargs)

    if len(images) == 1:
        return images[0].id

    elif len(images) > 1:
        raise errors.AnsibleFilterError(
            "More than 1 instance was found with name {0} in region {1}"
            .format(name, region)
        )
    else:
        raise errors.AnsibleFilterError(
            "No instance was found with name {0} in region {1}"
            .format(name, region)
        )

def get_instance_id_by_name(name, region, state="running"):
    """Retrieve the instance id of an ec2 instance by name.
    Args:
        name (str): The name of the instance id you are retrieving the key for.
        region (str): The region in which the elb resides.

    Kwargs:
        state (str): A valid instance state to add to the search filter.
            The following are valid states: pending, running, stopped,
            stopping, rebooting, shutting-down, terminated.
            default=None

    Basic Usage:
        >>> name = 'base'
        >>> region = 'us-west-2'
        >>> instance_id = get_instance_id_by_name(name, region)
        u'i-1234567'

    Returns:
        String
    """
    instance_id = (
        get_instance(name, region, return_key="id", state=state)
    )
    return instance_id


class FilterModule(object):
    ''' Ansible core jinja2 filters '''

    def filters(self):
        return {
            'get_vpc_id_by_name': get_vpc_id_by_name,
            'get_ami_image_id': get_ami_image_id,
            'get_instance_id_by_name': get_instance_id_by_name,
            'get_subnet_ids': get_subnet_ids,
            'get_sg': get_sg,
            'get_sg_cidrs': get_sg_cidrs,
            'get_older_images': get_older_images,
            'get_instance': get_instance,
            'get_all_vpcs_info_except': get_all_vpcs_info_except,
            'get_route_table_ids': get_route_table_ids,
            'get_all_route_table_ids': get_all_route_table_ids,
            'get_all_route_table_ids_except': get_all_route_table_ids_except,
            'get_subnet_ids_in_zone': get_subnet_ids_in_zone,
            'latest_ami_id': latest_ami_id,
            'get_rds_address': get_rds_address,
            'zones': zones,
            'get_sqs': get_sqs,
            'get_instance_profile': get_instance_profile,
            'get_server_certificate': get_server_certificate,
            'vpc_exists': vpc_exists,
            "get_dynamodb_base_arn": get_dynamodb_base_arn,
            'get_kinesis_stream_arn': get_kinesis_stream_arn,
        }
