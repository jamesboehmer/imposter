from __future__ import print_function
import getpass
import logging
import netifaces
import os
import subprocess
import sys
from hashlib import md5
import requests

from flask import Flask
from gunicorn import config
from gunicorn.app.base import Application

from imposter.routes import register_routes

logging.config.fileConfig('{}/logging.ini'.format(os.path.dirname(os.path.realpath(__file__))))
logger = logging.getLogger('imposter')

app = Flask(__name__)

register_routes(app)


class FlaskApplication(Application):
    def init(self, parser, opts, args):
        app.config['AWS_PROFILE'] = opts.profile
        if opts.awsconfig:
            app.config['AWS_CONFIG_FILE'] = opts.awsconfig
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
                # _parser.add_argument('--stop', action='store_true', help="Stop the imposter service")

        self.cfg.settings['profile'] = ProfileSettings()
        self.cfg.settings['awsconfig'] = AWSConfigSettings()
        self.cfg.settings['stop'] = StopSettings()
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
            except IOError as ioe:
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

        # if 169.254.169.254 doesn't exist we should add it as an alias
        if self.cfg.address[0][0] == '169.254.169.254':
            privip = [a.get('addr') for a in netifaces.ifaddresses('lo0')[netifaces.AF_INET]]
            if '169.254.169.254' not in privip:
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
