import datetime
import os
from threading import BoundedSemaphore

from boto import sts
from boto.provider import ProfileNotFoundError
from boto.pyami.config import Config
from werkzeug.local import LocalProxy

try:
    os.path.expanduser('~')
    expanduser = os.path.expanduser
except (AttributeError, ImportError):
    expanduser = (lambda x: x)

ROLE_SESSION_NAME = 'imposter-sts-client'
config_lock = BoundedSemaphore(1)


def assume_identity(config):
    # if AWS_PROFILE was the option last used, and it didn't require assuming a role
    if config.get('AWS_PROFILE_REFRESH_NOT_NEEDED'):
        return None

    _config_lock = config.get('CONFIG_LOCK') or config_lock
    _config_lock.acquire()

    try:
        if 'AWS_PROFILE' in list(config.keys()) + list(os.environ.keys()):
            assumed_role = config.get('assumed_role')
            if assumed_role and not assumed_role.credentials.is_expired(time_offset_seconds=900):
                return False

            # fetch the credentials from the aws configs
            shared_credentials = config.get('AWS_SHARED_CREDENTIALS')

            if not shared_credentials:
                config_path = config.get('AWS_CONFIG_FILE') or os.environ.get('AWS_CONFIG_FILE') or os.path.join(
                    expanduser('~'), '.aws', 'config')
                credentials_path = (config.get('AWS_CONFIG_FILE') or os.environ.get('AWS_CONFIG_FILE') or os.path.join(
                    expanduser('~'), '.aws', 'credentials')).replace('/config', '/credentials')

                shared_credentials = Config(do_load=False)
                if os.path.isfile(credentials_path):
                    shared_credentials.load_from_path(credentials_path)
                if os.path.isfile(config_path):
                    shared_credentials.load_from_path(config_path)
                config['AWS_SHARED_CREDENTIALS'] = shared_credentials

            profile_key = config.get('AWS_PROFILE') or os.environ.get('AWS_PROFILE')
            if not shared_credentials.has_section(profile_key):
                profile_key = 'profile {}'.format(profile_key)
            if not shared_credentials.has_section(profile_key):
                raise ProfileNotFoundError('Profile {} not found'.format(config['AWS_PROFILE']))

            # no matter what, get the access and secret key pair
            if all([shared_credentials.has_option(profile_key, x) for x in
                    ('aws_access_key_id', 'aws_secret_access_key')]):
                aws_access_key_id = shared_credentials.get(profile_key, 'aws_access_key_id')
                aws_secret_access_key = shared_credentials.get(profile_key, 'aws_secret_access_key')
            elif shared_credentials.has_option(profile_key, 'source_profile'):
                source_profile_key = shared_credentials.get(profile_key, 'source_profile')
                if not shared_credentials.has_section(source_profile_key):
                    source_profile_key = 'profile {}'.format(source_profile_key)
                if not shared_credentials.has_section(source_profile_key):
                    raise ProfileNotFoundError(
                        'Source profile {} for profile {} not found'.format(
                            shared_credentials.get(profile_key, 'source_profile'),
                            config['AWS_PROFILE']))

                # source_section = shared_credentials['_sections'][source_profile_key]
                if all([shared_credentials.has_option(source_profile_key, x) for x in
                        ('aws_access_key_id', 'aws_secret_access_key')]):
                    aws_access_key_id = shared_credentials.get(source_profile_key, 'aws_access_key_id')
                    aws_secret_access_key = shared_credentials.get(source_profile_key, 'aws_secret_access_key')
                else:
                    raise ProfileNotFoundError(
                        'Source profile {} for profile {} has no access or secret key'.format(
                            shared_credentials.get(profile_key, 'source_profile'),
                            config['AWS_PROFILE']))

            # if there's a role_arn, use it to assume a role
            if shared_credentials.has_option(profile_key, 'role_arn'):
                role_arn = shared_credentials.get(profile_key, 'role_arn')
                sts_connection = sts.STSConnection(aws_access_key_id=aws_access_key_id,
                                                   aws_secret_access_key=aws_secret_access_key)
                config['assumed_role'] = sts_connection.assume_role(role_arn,
                                                                    ROLE_SESSION_NAME, policy=None,
                                                                    duration_seconds=960)
                config['role_last_updated'] = datetime.datetime.utcnow().isoformat()[:19] + 'Z'

            return True

        else:
            return None

    finally:
        _config_lock.release()


def _get_assumed_role(config):
    _ = assume_identity(config)
    return config.get('assumed_role')


def get_assumed_role(config):
    return LocalProxy(lambda: _get_assumed_role(config))
