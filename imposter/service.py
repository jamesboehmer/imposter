from __future__ import print_function

import getpass
import logging
import os
import subprocess
import sys
from hashlib import md5

import requests
from flask import Flask
from gunicorn import config
from gunicorn.app.base import Application

from imposter.routes import register_routes
from imposter.helpers import get_assumed_role

logging.config.fileConfig('{}/logging.ini'.format(os.path.dirname(os.path.realpath(__file__))))
logger = logging.getLogger('imposter')

app = Flask(__name__)

register_routes(app)


class FlaskApplication(Application):
    def init(self, parser, opts, args):
        app.config['AWS_PROFILE'] = opts.profile
        if opts.awsconfig:
            app.config['AWS_CONFIG_FILE'] = opts.awsconfig

        # preload all of the profiles
        if opts.profile:
            _ = get_assumed_role(app.config, opts.profile).credentials
            shared_credentials = app.config['AWS_SHARED_CREDENTIALS']
            _ = get_assumed_role(app.config, app.config.get('AWS_PROFILE')).credentials
            profiles = [profile.replace('profile ', '') for profile in shared_credentials.sections() if
                        profile.startswith('profile ') and shared_credentials.get(profile, 'source_profile')]

            for profile in profiles:
                try:
                    logger.debug("Loading profile: {}".format(profile))
                    _ = get_assumed_role(app.config, profile).credentials
                except Exception as e:
                    logger.error("Couldn't assume role {}: {}".format(profile, str(e)))

        return {}

    def load_config(self):
        # parse console args

        class ProfileSettings(config.Setting):
            name = "profile"
            # action = "append"
            section = "AWS CLI Profile"
            cli = ["--profile"]
            meta = "AWS_PROFILE"

            validator = config.validate_string
            desc = section

            def add_option(self, _parser):
                if not self.cli:
                    return
                _args = tuple(self.cli)

                help_txt = "%s [%s]" % (self.short, self.default)
                help_txt = help_txt.replace("%", "%%")

                kwargs = {
                    "dest": self.name,
                    "action": self.action or "store",
                    "type": self.type or str,
                    "default": None,
                    "help": help_txt
                }

                if self.meta is not None:
                    kwargs['metavar'] = self.meta

                if kwargs["action"] != "store":
                    kwargs.pop("type")

                if self.nargs is not None:
                    kwargs["nargs"] = self.nargs

                if self.const is not None:
                    kwargs["const"] = self.const

                kwargs['required'] = False

                _group = _parser.add_mutually_exclusive_group(required=True)
                _group.add_argument(*_args, **kwargs)
                _group.add_argument('--stop', action='store_true', help="Stop the imposter service")
                _group.add_argument('--roles', action='store_true', help="List available roles")
                _group.add_argument('--status', action='store_true', help="Imposter service status")

        class AWSConfigSettings(config.Setting):
            name = "awsconfig"
            section = "AWS CLI Config File location"
            cli = ["--awsconfig"]
            meta = "AWS_CONFIG_FILE"
            validator = config.validate_string
            desc = section

            def add_option(self, _parser):
                _parser.add_argument('--awsconfig', action='store', type=str, default=None, required=False,
                                     help='AWS CLI Config File Location')

        class StopSettings(config.Setting):
            name = "stop"
            section = "Stop the imposter service"
            cli = ["--stop"]
            meta = "STOP"
            validator = lambda *_: True
            desc = section

            def add_option(self, _parser):
                pass

        class StatusSettings(config.Setting):
            name = "status"
            section = "Imposter service status"
            cli = ["--status"]
            meta = "STATUS"
            validator = lambda *_: True
            desc = section

            def add_option(self, _parser):
                pass

        class RolesSettings(config.Setting):
            name = "roles"
            section = "List available roles"
            cli = ["--roles"]
            meta = "ROLES"
            validator = lambda *_: True
            desc = section

            def add_option(self, _parser):
                pass

        self.cfg.settings['profile'] = ProfileSettings()
        self.cfg.settings['awsconfig'] = AWSConfigSettings()
        self.cfg.settings['stop'] = StopSettings()
        self.cfg.settings['status'] = StatusSettings()
        self.cfg.settings['roles'] = RolesSettings()
        self.cfg.settings['bind'].default = ['169.254.169.254:80']
        self.cfg.settings['bind'].value = self.cfg.settings['bind'].default

        tmpdir = '/tmp'  # tempfile.gettempdir()
        address = '{}:{}'.format(*self.cfg.address[0])
        pidfile = '{}/imposter.{}'.format(tmpdir, md5(address).hexdigest())

        logger.debug("pidfile: {}".format(pidfile))

        self.cfg.settings['pidfile'].default = pidfile
        self.cfg.settings['pidfile'].value = self.cfg.settings['pidfile'].default

        parser = self.cfg.parser()

        args = parser.parse_args()
        # redo the pid file in case there was a different bind arg
        tmpdir = '/tmp'  # tempfile.gettempdir()
        address = '{}'.format(args.bind[0] if args.bind else self.cfg.settings['bind'].value[0])
        pidfile = '{}/imposter.{}'.format(tmpdir, md5(address).hexdigest())
        self.cfg.settings['pidfile'].value = pidfile
        if args.status:
            try:
                url = 'http://{}:{}/status'.format(self.cfg.address[0][0], self.cfg.address[0][1], args.profile)
                logger.debug("Querying {}".format(url))
                r = requests.get(url)
                print(str(r.content))
            except Exception as _:
                print('Imposter service not reachable: {}'.format(url))
                sys.exit(1)
            sys.exit(0)

        if args.stop:
            try:
                logger.debug("Reading from {}".format(pidfile))
                with open(pidfile, 'rb') as p:
                    pid = p.read()
                    logger.debug("piduid: {}".format(pid))
                    thisuid = os.getuid()
                    pidfile_stats = os.stat(pidfile)
                    cmd = ['kill', pid]
                    if thisuid != pidfile_stats.st_uid:
                        cmd = ['sudo'] + cmd
                    proc = subprocess.Popen(' '.join(cmd), shell=True)
                    while proc.returncode is None:
                        try:
                            proc.wait()
                        except KeyboardInterrupt:
                            pass
                    sys.exit(proc.returncode)
            except IOError:
                logger.error("Couldn't open pidfile: {}".format(pidfile))
            except Exception as e:
                logger.error(str(e))
            finally:
                sys.exit(0)

        # optional settings from apps
        cfg = self.init(parser, args, args.args)

        # Load up the any app specific configuration
        if cfg and cfg is not None:
            for k, v in cfg.items():
                self.cfg.set(k.lower(), v)

        if args.config:
            self.load_config_from_file(args.config)
        else:
            default_config = config.get_default_config_file()
            if default_config is not None:
                self.load_config_from_file(default_config)

        # Lastly, update the configuration with any command line
        # settings.
        for k, v in args.__dict__.items():
            if v is None:
                continue
            if k == "args":
                continue
            self.cfg.set(k.lower(), v)

        if args.roles:
            try:
                # It must exist, so we know the host and port
                url = 'http://{}:{}/roles'.format(self.cfg.address[0][0], self.cfg.address[0][1], args.profile)
                r = requests.get(url)
                print(str(r.content))
                sys.exit(0)
            except requests.ConnectionError:
                print('Imposter service not running: {}'.format(url), file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(str(e), file=sys.stderr)
                sys.exit(1)

        # Check if the pid exists first.  If so, try to request a role change
        try:
            os.stat(pidfile)
            # It must exist, so we know the host and port
            url = 'http://{}:{}/roles/{}'.format(self.cfg.address[0][0], self.cfg.address[0][1], args.profile)
            r = requests.post(url)
            print(str(r.content))
            sys.exit(0)
        except OSError:
            pass

        # Check for misconfigred AWS CLI
        _tmpconfig = {}
        _ = get_assumed_role(_tmpconfig, args.profile).credentials
        shared_credentials = _tmpconfig['AWS_SHARED_CREDENTIALS']
        for field in ['aws_access_key_id', 'aws_secret_access_key']:
            if shared_credentials.get('default', field) or shared_credentials.get('profile default', field):
                print(
                    '''*******
Your AWS CLI configuration has a "default" profile with an "{}" attribute.
The AWS SDKs will attempt to use this before going to the EC2 Metadata service.
Move your default credentials to a new section, and update the profiles which depend on it
*******'''.format(
                        field), file=sys.stderr)
                sys.exit(1)

        # if 169.254.169.254 doesn't exist we should add it as an alias
        if self.cfg.address[0][0] == '169.254.169.254':
            interfaces = subprocess.Popen('ifconfig lo0 inet', shell=True, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE).communicate()[0]
            if '169.254.169.254' not in interfaces:
                cmd = ['ifconfig', 'lo0', 'alias', '169.254.169.254']
                if os.getuid() != 0:
                    cmd = ['sudo'] + cmd
                logger.info('Adding 169.254.169.254 alias to lo0: {}'.format(' '.join(cmd)))
                proc = subprocess.Popen(' '.join(cmd), shell=True)
                while proc.returncode is None:
                    try:
                        proc.wait()
                    except KeyboardInterrupt:
                        pass
                if proc.returncode != 0:
                    logger.error('Error calling {}'.format(' '.join(cmd)))
                    sys.exit(1)

        if self.cfg.address[0][1] < 1024 and os.getuid() != 0:
            # restart this program as root
            logger.info('Switching to root to run on a privileged port.')
            username = getpass.getuser()
            cmd = ['sudo', sys.executable] + sys.argv + ['--user', username]
            proc = subprocess.Popen(' '.join(cmd), shell=True, cwd=os.getcwd())
            while proc.returncode is None:
                try:
                    proc.wait()
                except KeyboardInterrupt:
                    pass
            sys.exit(proc.returncode)

    def load(self):
        return app


def main():
    FlaskApplication().run()


if __name__ == '__main__':
    main()
