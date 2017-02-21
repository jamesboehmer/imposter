import getpass
import os
import subprocess
import sys

import netifaces
from flask import Flask
from gunicorn import config
from gunicorn.app.base import Application
import logging
from imposter.routes import register_routes

logging.config.fileConfig('{}/logging.ini'.format(os.path.dirname(os.path.realpath(__file__))))
logger = logging.getLogger('imposter')

# logger = Logger()
app = Flask(__name__)
# app.config['DEBUG'] = True

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

                kwargs['required'] = True

                _parser.add_argument(*_args, **kwargs)

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

        self.cfg.settings['profile'] = ProfileSettings()
        self.cfg.settings['awsconfig'] = AWSConfigSettings()
        self.cfg.settings['bind'].default = ['169.254.169.254:80']
        self.cfg.settings['bind'].value = self.cfg.settings['bind'].default

        parser = self.cfg.parser()

        args = parser.parse_args()

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
                status = subprocess.Popen(' '.join(cmd), shell=True)
                # if status.returncode != 0:
                #     ogger.error('Error calling {}'.format(' '.join(cmd)))
                #     sys.exit(1)
        if self.cfg.address[0][1] < 1024 and os.getuid() != 0:
            # restart this program as root
            logger.info('Switching to root to run on a privileged port.')
            username = getpass.getuser()
            cmd = ['sudo', 'PYTHONPATH=.', sys.executable] + sys.argv + ['--user', username]
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
