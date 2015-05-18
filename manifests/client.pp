# == Class: ssh::client
#
# Manage and configure the OpenSSH client.
#
# === Parameters
#
# [*package_name*]
#   Name of the OpenSSH client package.
#
# [*manage_firewall*]
#   If `true` a puppetlabs-firewall module firewall rule will be created to
#   allow outgoing SSH trafic.
#
# === Authors
#
# Tyler Yahn <tyler@moonshadowmobile.com>
#
class ssh::client (
  $package_name    = hiera("${module_name}::client::package_name"),
  $manage_firewall = hiera("${module_name}::client::manage_firewall", true),
) {
  include 'ssh'

  validate_string($package_name)
  validate_bool($manage_firewall)

  ensure_packages($package_name)

  if $manage_firewall {
    firewall { '500 Allow SSH':
      chain  => 'OUTPUT',
      proto  => 'tcp',
      dport  => 22,
      action => 'accept',
    }
  }
}
