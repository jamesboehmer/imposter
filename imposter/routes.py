import json
from collections import OrderedDict

from flask import request, Response
from flask.json import jsonify

from imposter.helpers import get_assumed_role, set_default_profile


def register_routes(app):
    @app.route('/latest/meta-data/iam/')
    def latest_metadata_iam():
        return Response(content_type='text/plain', response='\n'.join(['info', 'security-credentials/']), status=200)

    @app.route('/latest/meta-data/iam/info/')
    def latest_metadata_iam_info():
        assumed_role = get_assumed_role(app.config, app.config.get('AWS_PROFILE'))
        user = assumed_role.user
        profile = OrderedDict([
            ('Code', 'Success'),
            ('LastUpdated', app.config.get('role_last_updated', {}).get(app.config.get('AWS_PROFILE'))),
            ('InstanceProfileArn', user.arn),
            ('InstanceProfileId', user.assume_role_id),
        ]
        )
        return Response(content_type='text/plain', response=json.dumps(profile), status=200)

    @app.route('/latest/meta-data/iam/security-credentials/')
    def latest_metadata_iam_securitycredentials():
        return Response(content_type='text/plain', response=app.config.get('AWS_PROFILE'), status=200)

    @app.route('/latest/meta-data/iam/security-credentials/<alias>')
    def latest_metadata_iam_securitycredentials_alias(alias):
        app.logger.debug(str(request))
        assumed_role = get_assumed_role(app.config, alias)
        credentials = assumed_role.credentials
        role = OrderedDict([
            ('Code', 'Success'),
            ('LastUpdated', app.config.get('role_last_updated', {}).get(alias)),
            ('Type', 'AWS-HMAC'),
            ('AccessKeyId', credentials.access_key),
            ('SecretAccessKey', credentials.secret_key),
            ('Token', credentials.session_token),
            ('Expiration', credentials.expiration),
        ]
        )
        return Response(content_type='text/plain', response=json.dumps(role), status=200)

    @app.route('/roles')
    def roles():
        # get credentials at least once to ensure the config was loaded
        _ = get_assumed_role(app.config, app.config.get('AWS_PROFILE')).credentials
        roles = [profile.replace('profile ', '') for profile in app.config['AWS_SHARED_CREDENTIALS'].sections() if
                 profile.startswith('profile ')]
        roles.sort()
        return jsonify(roles=roles)

    @app.route('/status')
    def status():
        return Response(content_type='text/plain', response='OK', status=200)

    @app.route('/roles/<profile>', methods=['GET', 'POST'])
    def roles_profile(profile):
        assumed_role = get_assumed_role(app.config, profile)
        try:
            user = assumed_role.user
            if request.method == 'POST':
                set_default_profile(app.config, profile)
            _profile = OrderedDict([
                ('Code', 'Success'),
                ('LastUpdated', app.config.get('role_last_updated', {}).get(profile)),
                ('InstanceProfileArn', user.arn),
                ('InstanceProfileId', user.assume_role_id),
            ])
            return jsonify(**_profile)
        except _:
            return Response(content_type='text/plain', response='Role {} not found'.format(profile),
                            status=404)

    @app.route('/<path>')
    def basepath(path):
        return Response(content_type='text/plain', response='URI Path "/{}" not yet implemented\n'.format(path),
                        status=200)
