import json
from collections import OrderedDict

from flask import request, Response

from imposter.helpers import get_assumed_role


def register_routes(app):
    assumed_role = get_assumed_role(app.config)

    @app.route('/latest/meta-data/iam/')
    def latest_metadata_iam():
        return Response(content_type='text/plain', response='\n'.join(['info', 'security-credentials/']), status=200)

    @app.route('/latest/meta-data/iam/info/')
    def latest_metadata_iam_info():
        user = assumed_role.user
        profile = OrderedDict([
            ('Code', 'Success'),
            ('LastUpdated', app.config.get('role_last_updated')),
            ('InstanceProfileArn', user.arn),
            ('InstanceProfileId', user.assume_role_id),
        ]
        )
        return Response(content_type='text/plain', response=json.dumps(profile), status=200)

    @app.route('/latest/meta-data/iam/security-credentials/')
    def latest_metadata_iam_securitycredentials():
        app.logger.debug(str(request))
        return Response(content_type='text/plain', response=app.config.get('AWS_PROFILE'), status=200)

    @app.route('/latest/meta-data/iam/security-credentials/<alias>')
    def latest_metadata_iam_securitycredentials_alias(alias):
        app.logger.debug(str(request))
        credentials = assumed_role.credentials
        role = OrderedDict([
            ('Code', 'Success'),
            ('LastUpdated', app.config.get('role_last_updated')),
            ('Type', 'AWS-HMAC'),
            ('AccessKeyId', credentials.access_key),
            ('SecretAccessKey', credentials.secret_key),
            ('Token', credentials.session_token),
            ('Expiration', credentials.expiration),
        ]
        )
        return Response(content_type='text/plain', response=json.dumps(role), status=200)

    @app.route('/<path>')
    def basepath(path):
        return Response(content_type='text/plain', response='URI Path "/{}" not yet implemented\n'.format(path), status=200)
