from setuptools import setup, find_packages

setup(name='imposter',
      version='0.0.5',
      description='AWS EC2 Metadata Imposter Service',
      author='James Boehmer',
      author_email='james.boehmer@gmail.com',
      url='https://github.com/jamesboehmer/imposter',
      packages=find_packages(),
      py_modules=['imposter'],
      include_package_data=True,
      install_requires=['Flask==0.12', 'gunicorn==19.6.0', 'boto==2.45.0', 'netifaces==0.10.5'],
      entry_points={
          'console_scripts': [
              'imposter=imposter.service:main',
          ],
      },
      )
