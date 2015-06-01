# == Class: ssh::server
#
# Manage and configure the OpenSSH server.
#
# === Parameters
#
# [*package_name*]
#   Name of the openssh-server package.
#
# [*sshd_config*]
#   File path for the SSH server configuration.
#
# [*service_name*]
#   Name of the openssh-server service.
#
# [*port*]
#   Port the openssh-server listens on.
#
# [*listen_address*]
#   Address the openssh-server listens on.
#
# [*protocol*]
#   SSH protocol.
#
# [*host_keys*]
#   Host authentication keys.
#
# [*use_privilege_separation*]
#   Openssh-server configuration option.
#
# [*key_regeneration_interval*]
#   Openssh-server configuration option.
#
# [*server_key_bits*]
#   Openssh-server configuration option.
#
# [*syslog_facility*]
#   Openssh-server configuration option.
#
# [*log_level*]
#   Openssh-server configuration option.
#
# [*login_grace_time*]
#   Openssh-server configuration option.
#
# [*permit_root_login*]
#   Openssh-server configuration option.
#
# [*strict_modes*]
#   Openssh-server configuration option.
#
# [*rsa_authentication*]
#   Openssh-server configuration option.
#
# [*pubkey_authentication*]
#   Openssh-server configuration option.
#
# [*authorized_keys_file*]
#   Openssh-server configuration option.
#
# [*ignore_rhosts*]
#   Openssh-server configuration option.
#
# [*rhosts_RSA_authentication*]
#   Openssh-server configuration option.
#
# [*hostbased_authentication*]
#   Openssh-server configuration option.
#
# [*ignore_user_known_hosts*]
#   Openssh-server configuration option.
#
# [*permit_empty_passwords*]
#   Openssh-server configuration option.
#
# [*challenge_response_authentication*]
#   Openssh-server configuration option.
#
# [*password_authentication*]
#   Openssh-server configuration option.
#
# [*kerberos_authentication*]
#   Openssh-server configuration option.
#
# [*kerberos_get_AFS_token*]
#   Openssh-server configuration option.
#
# [*kerberos_or_local_passwd*]
#   Openssh-server configuration option.
#
# [*kerberos_ticket_cleanup*]
#   Openssh-server configuration option.
#
# [*gssapi_authentication*]
#   Openssh-server configuration option.
#
# [*gssapi_cleanup_credentials*]
#   Openssh-server configuration option.
#
# [*x11_forwarding*]
#   Openssh-server configuration option.
#
# [*x11_display_offset*]
#   Openssh-server configuration option.
#
# [*print_motd*]
#   Openssh-server configuration option.
#
# [*print_last_log*]
#   Openssh-server configuration option.
#
# [*tcp_keep_alive*]
#   Openssh-server configuration option.
#
# [*use_login*]
#   Openssh-server configuration option.
#
# [*max_startups*]
#   Openssh-server configuration option.
#
# [*banner*]
#   Openssh-server configuration option.
#
# [*accept_env*]
#   Openssh-server configuration option.
#
# [*use_PAM*]
#   Openssh-server configuration option.
#
# === Authors
#
# Tyler Yahn <tyler@moonshadowmobile.com>
#
class ssh::server (
  $package_name                      = hiera("${module_name}::server::package_name", 'openssh-server'),
  $service_name                      = hiera("${module_name}::server::service_name"),
  $sshd_config                       = hiera("${module_name}::server::sshd_config", '/etc/ssh/sshd_config'),
  $sshd_config_template              = hiera("${module_name}::server::sshd_config_template", "${module_name}/sshd_config.erb"),
  $port                              = hiera("${module_name}::server::port", 22),
  $listen_address                    = hiera("${module_name}::server::listen_address", '0.0.0.0'),
  $protocol                          = hiera("${module_name}::server::protocol", 2),
  $host_keys                         = hiera_array("${module_name}::server::host_keys", [ '/etc/ssh/ssh_host_rsa_key', '/etc/ssh/ssh_host_dsa_key', '/etc/ssh/ssh_host_ecdsa_key', ]),
  $use_privilege_separation          = hiera("${module_name}::server::use_privilege_separation", true),
  $key_regeneration_interval         = hiera("${module_name}::server::key_regeneration_interval", 3600),
  $server_key_bits                   = hiera("${module_name}::server::server_key_bits", 768),
  $syslog_facility                   = hiera("${module_name}::server::syslog_facility", 'AUTH'),
  $log_level                         = hiera("${module_name}::server::log_level", 'INFO'),
  $login_grace_time                  = hiera("${module_name}::server::login_grace_time", 120),
  $permit_root_login                 = hiera("${module_name}::server::permit_root_login", 'no'),
  $strict_modes                      = hiera("${module_name}::server::strict_modes", true),
  $rsa_authentication                = hiera("${module_name}::server::rsa_authentication", true),
  $pubkey_authentication             = hiera("${module_name}::server::pubkey_authentication", true),
  $authorized_keys_file              = hiera("${module_name}::server::authorized_keys_file", '%h/.ssh/authorized_keys'),
  $ignore_rhosts                     = hiera("${module_name}::server::ignore_rhosts", true),
  $rhosts_RSA_authentication         = hiera("${module_name}::server::rhosts_RSA_authentication", false),
  $hostbased_authentication          = hiera("${module_name}::server::hostbased_authentication", false),
  $ignore_user_known_hosts           = hiera("${module_name}::server::ignore_user_known_hosts", false),
  $permit_empty_passwords            = hiera("${module_name}::server::permit_empty_passwords", false),
  $challenge_response_authentication = hiera("${module_name}::server::challenge_response_authentication", false),
  $password_authentication           = hiera("${module_name}::server::password_authentication", false),
  $kerberos_authentication           = hiera("${module_name}::server::kerberos_authentication", false),
  $kerberos_get_AFS_token            = hiera("${module_name}::server::kerberos_get_AFS_token", false),
  $kerberos_or_local_passwd          = hiera("${module_name}::server::kerberos_or_local_passwd", true),
  $kerberos_ticket_cleanup           = hiera("${module_name}::server::kerberos_ticket_cleanup", true),
  $gssapi_authentication             = hiera("${module_name}::server::gssapi_authentication", false),
  $gssapi_cleanup_credentials        = hiera("${module_name}::server::gssapi_cleanup_credentials", true),
  $x11_forwarding                    = hiera("${module_name}::server::x11_forwarding", false),
  $x11_display_offset                = hiera("${module_name}::server::x11_display_offset", undef),
  $print_motd                        = hiera("${module_name}::server::print_motd", false),
  $print_last_log                    = hiera("${module_name}::server::print_last_log", true),
  $tcp_keep_alive                    = hiera("${module_name}::server::tcp_keep_alive", true),
  $use_login                         = hiera("${module_name}::server::use_login", false),
  $max_startups                      = hiera("${module_name}::server::max_startups", '10:30:60'),
  $banner                            = hiera("${module_name}::server::banner", '/etc/issue.net'),
  $accept_env                        = hiera_array("${module_name}::server::accept_env", [ 'LANG', 'LC_*', ]),
  $use_PAM                           = hiera("${module_name}::server::use_PAM", true),
  $manage_firewall                   = hiera("${module_name}::client::manage_firewall", true),
) {
  include 'ssh'

  validate_string($package_name)
  validate_string($service_name)
  validate_string($authorized_keys_file)
  validate_string($max_startups)
  validate_string($listen_address)
  validate_absolute_path($sshd_config)
  validate_absolute_path($banner)
  validate_integer($port)
  validate_integer($key_regeneration_interval)
  validate_integer($server_key_bits)
  validate_integer($login_grace_time)
  validate_re($protocol, ['1', '2', '1,2', '2,1'])
  validate_re($syslog_facility, ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7'])
  validate_re($log_level, ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3'])
  validate_re($permit_root_login, ['yes', 'without-password', 'forced-commands-only', 'no'])
  validate_re($x11_display_offset, ['^\d+$', ''])
  validate_array($host_keys)
  validate_array($accept_env)
  validate_bool($use_privilege_separation)
  validate_bool($strict_modes)
  validate_bool($rsa_authentication)
  validate_bool($pubkey_authentication)
  validate_bool($ignore_rhosts)
  validate_bool($rhosts_RSA_authentication)
  validate_bool($hostbased_authentication)
  validate_bool($ignore_user_known_hosts)
  validate_bool($permit_empty_passwords)
  validate_bool($challenge_response_authentication)
  validate_bool($password_authentication)
  validate_bool($kerberos_authentication)
  validate_bool($kerberos_get_AFS_token)
  validate_bool($kerberos_or_local_passwd)
  validate_bool($kerberos_ticket_cleanup)
  validate_bool($gssapi_authentication)
  validate_bool($gssapi_cleanup_credentials)
  validate_bool($x11_forwarding)
  validate_bool($print_motd)
  validate_bool($print_last_log)
  validate_bool($tcp_keep_alive)
  validate_bool($use_login)
  validate_bool($use_PAM)
  validate_bool($manage_firewall)

  ensure_packages($package_name)

  concat { $sshd_config:
    ensure  => present,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    warn    => true,
    require => Package[$package_name],
    notify  => Service[$service_name],
  }

  concat::fragment { 'sshd_body':
    ensure  => present,
    target  => $sshd_config,
    content => template($sshd_config_template),
    order   => '01',
  }

  if $manage_firewall {
    firewall { '300 Accept SSH':
      chain  => 'INPUT',
      proto  => 'tcp',
      dport  => $port,
      action => 'accept',
    }
  }

  service { $service_name:
    ensure => running,
    enable => true,
  }
}
