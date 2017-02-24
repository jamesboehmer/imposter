EC2 Metadata Service Imposter
=============================

This service was created to ease the usage of AWS SDK tools with using
assumed roles in your development environment.

Installation
------------

``pip install imposter``

Usage
-----

Launching the service
~~~~~~~~~~~~~~~~~~~~~

``imposter --profile <AWS CLI profile name> [--bind [host]:port](169.254.169.254:80) [-D] (daemonize)``

If the service detects you do not have the private IP address
169.254.169.254, it will attempt to create it for you with sudo. It will
also ask for credentials so that you can run the service on privileged
ports.

Stopping the service
~~~~~~~~~~~~~~~~~~~~

``imposter --stop``

Listing roles
~~~~~~~~~~~~~

``imposter --roles``

Switching roles
~~~~~~~~~~~~~~~

``imposter --profile <AWS CLI profile name>``

If the service is running, it will attempt to switch the active role. If
not, it will launch it. Switching roles is equivalent to running

``curl -XPOST http://169.254.169.254/roles/<profilename>``

Checking service status
~~~~~~~~~~~~~~~~~~~~~~~

``imposter --status``

Your AWS CLI config
-------------------

Your AWS CLI config should *not* have credentials in the ``default``
profile, otherwise the AWS SDK will look there for credentials before
looking for the EC2 Metadata service. Instead, have your config profiles
point to a separate, non-default section with your credentials, e.g.

::

    [profile teamrole1]
    role_arn = arn:aws:iam::123456789012:role/teamrole1
    source_profile = myidentity
    role_session_name = teamrole1

    [profile teamrole2]
    role_arn = arn:aws:iam::123456789012:role/teamrole2
    source_profile = myidentity
    role_session_name = teamrole2

    [myidentity]
    aws_access_key_id = ABCDEFGHIJKLMNOPQRST
    aws_secret_access_key = abcdefghij1234567890abcdefghij1234567890