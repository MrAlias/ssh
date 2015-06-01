# ssh

#### Table of Contents

1. [Overview](#overview)
2. [Module Description](#module-description)
3. [Setup](#setup)
    * [What ssh affects](#what-ssh-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with ssh](#beginning-with-ssh)
4. [Reference](#reference)
    * [Private Classes](#private-classes)
    * [Public Classes](#private-classes)
5. [Limitations](#limitations)

## Overview

Provides a hiera customizable Puppet module to manage the OpenSSH service.

## Module Description

This module manages the OpenSSH server and clients with the `ssh::server` and `ssh::client` classes.  This includes the management of need configuration files and the OpenSSH service itself.

## Setup

### What ssh affects

* OpenSSH packages.
* The OpenSSH server service.
* The OpenSSH server configuration files.
* Via the puppetlabs-firewall module this module can affect the system firewall.

### Setup Requirements

The modules classes are built with hiera assumed to be its back end.  This means that hiera will need to be correctly setup on versions of Puppet <= 2, and should be fine by default for Puppet >= 3.0

### Beginning with ssh

#### Setting up an SSH server

To get started with a bare-bones SSH server:

```puppet
class { 'ssh::server': }
```

#### Setting up an SSH client

Making sure to have a functional SSH client is simply achieved with the following:

```puppet
class { 'ssh::client': }
```

## Reference

### Private Classes

#### ssh

The main ssh class is not meant to be called directly.  Rather it acts as a basis for the client and server classes.

##### `ssh::base_packages`

Array of all the distribution specific universally required packages.

### Public Classes

#### ssh::client

##### `ssh::client::package_name`

If a package name other then the default distribution one is need to be installed, you can specify it here.

##### `ssh::client::manage_firewall`

By default `ssh::client` will manage needed firewall rule using the puppetlabs-firewall module.  Change this to false if this is not the desired behavior.

#### ssh::server

##### `ssh::server::package_name`

If a package name other then the default distribution one is need to be installed, you can specify it here.

##### `ssh::server::sshd_config`

Absolute file path for the SSH server configuration.

Defaults to */etc/ssh/sshd_config*

##### `ssh::server::service_name`

Name of the OpenSSH server service.

##### `ssh::server::port`

Port the OpenSSH server listens on.

Defaults to `22`.

##### `ssh::server::listen_address`

Address the OpenSSH server listens on.

Defaults to `'0.0.0.0'`.

##### `ssh::server::protocol`

SSH protocol to use.

Defaults to `2`.

##### `ssh::server::host_keys`

Array of file paths for the host authentication keys.

Defaults to `['/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_dsa_key', '/etc/ssh/ssh_host_ecdsa_key']`.

##### `ssh::server::use_privilege_separation`

Specifies whether the OpenSSH server separates privileges by creating an unprivileged child process to deal with incoming network traffic. After successful authentication, another process will be created that has the privilege of the authenticated user. The goal of privilege separation is to prevent privilege escalation by containing any corruption within the unprivileged processes.

Valid values are: `'yes'`, `'no'`, and `'sandbox'`. If set to `'sandbox'` then the pre-authentication unprivileged process is subject to additional restrictions.

##### `ssh::server::key_regeneration_interval`

In protocol version 1, the server key is automatically regenerated after this many seconds.

Defaults to `3600`.

##### `ssh::server::server_key_bits`

Defines the number of bits in the protocol version 1 server key.

Defaults to 768.

##### `ssh::server::syslog_facility`

Gives the facility code that is used when logging messages.

Valid values are: `'DAEMON'`, `'USER'`, `'AUTH'`, `'LOCAL0'`, `'LOCAL1'`, `'LOCAL2'`, `'LOCAL3'`, `'LOCAL4'`, `'LOCAL5'`, `'LOCAL6'`, `'LOCAL7'`.

Defaults to `'AUTH'`.

##### `ssh::server::log_level`

Specifies the verbosity level that is used when logging messages.

Valid values are: `'QUIET'`, `'FATAL'`, `'ERROR'`, `'INFO'`, `'VERBOSE'`, `'DEBUG'`, `'DEBUG1'`, `'DEBUG2'`, `'DEBUG3'`.

##### `ssh::server::login_grace_time`

The server disconnects after this time if the user has not successfully logged in.

Defaults to `120`.

##### `ssh::server::permit_root_login`

Specifies whether root can log in.

Valid values are: `'yes'`, `'without-password'`, `'forced-commands-only'`, `'no'`.

Defaults to `'no'`.

##### `ssh::server::strict_modes`

Specifies whether the OpenSSH service should check file modes and ownership of the user's files and home directory before accepting login.

Defaults to `true`.

##### `ssh::server::rsa_authentication`

Specifies whether pure RSA authentication is allowed.

Defaults to `true`.

##### `ssh::server::pubkey_authentication`

Specifies whether public key authentication is allowed.

Defaults to `true`.

##### `ssh::server::authorized_keys_file`

Specifies the file that contains the public keys that can be used for user authentication.

Defaults to `'%h/.ssh/authorized_keys'`.

##### `ssh::server::ignore_rhosts`

Specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication.

Defaults to `true`.

##### `ssh::server::rhosts_RSA_authentication`

Specifies whether rhosts or /etc/hosts.equiv authentication together with successful RSA host authentication is allowed.

Defaults to `false`.

##### `ssh::server::hostbased_authentication`

Specifies whether rhosts or */etc/hosts.equiv* authentication together with successful public key client host authentication is allowed.

Defaults to `false`.

##### `ssh::server::ignore_user_known_hosts`

Specifies whether the OpenSSH server should ignore the user's *~/.ssh/known_hosts* during RhostsRSAAuthentication or HostbasedAuthentication.

Defaults to `false`.

##### `ssh::server::permit_empty_passwords`

When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.

Defaults to `false`.

##### `ssh::server::challenge_response_authentication`

Specifies whether challenge-response authentication is allowed.

Defaults to `false`.

##### `ssh::server::password_authentication`

Specifies whether password authentication is allowed.

Defaults to `false`.

##### `ssh::server::kerberos_authentication`

Specifies whether the password provided by the user for PasswordAuthentication will be validated through the Kerberos KDC. 

Defaults to `false`.

##### `ssh::server::kerberos_get_AFS_token`

If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS token before accessing the user's home directory.

Defaults to `false`.

##### `ssh::server::kerberos_or_local_passwd`

If password authentication through Kerberos fails then the password will be validated via any additional local mechanism such as */etc/passwd*.

Defaults to `true`.

##### `ssh::server::kerberos_ticket_cleanup`

Specifies whether to automatically destroy the user's ticket cache file on logout.

Defaults to `true`.

##### `ssh::server::gssapi_authentication`

Specifies whether user authentication based on GSSAPI is allowed.

Defaults to `false`.

##### `ssh::server::gssapi_cleanup_credentials`

Specifies whether to automatically destroy the user's credentials cache on logout.

Defaults to `true`.

##### `ssh::server::x11_forwarding`

Specifies whether X11 forwarding is permitted.

Defaults to `false`.

##### `ssh::server::x11_display_offset`

Specifies the first display number available for OpenSSH server's X11 forwarding.

Defaults to `undef`.

##### `ssh::server::print_motd`

Specifies whether the OpenSSH server should print */etc/motd* when a user logs in interactively.

Defaults to `false`.

##### `ssh::server::print_last_log`

Specifies whether the OpenSSH server should print the date and time of the last user login when a user logs in interactively.

Defaults to `true`.

##### `ssh::server::tcp_keep_alive`

Specifies whether the system should send TCP keepalive messages to the other side.

Defaults to `true`.

##### `ssh::server::use_login`

Specifies whether the login service is used for interactive login sessions.

Defaults to `false`.

##### `ssh::server::max_startups`

Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon. Random early drop can be enabled by specifying the three colon separated values "start:rate:full".

Defaults to `'10:30:60'`.

##### `ssh::server::banner`

The contents of the specified file are sent to the remote user before authentication is allowed.

Defaults to `'/etc/issue.net'`.

##### `ssh::server::accept_env`

Specifies what environment variables sent by the client will be copied into the session's environ.

Defaults to `['LANG', 'LC_*']`.

##### `ssh::server::use_PAM`

Enables the Pluggable Authentication Module interface.

Defaults to `true`.

##### `ssh::server::manage_firewall`

Specifies if OpenSSH server specific firewall rules should be managed.

Defaults to `true`.

## Limitations

This module requires Puppet >= 3.0

This module has only been tested on Debian and RedHat based systems.
