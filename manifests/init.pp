# == Class: ssh
#
# Manages all common client and server requirements
#
# === Parameters
#
# [*base_packages*]
#   Array of all the universally required packages.
#
# === Authors
#
# Tyler Yahn <codingalias@gmail.com>
#
class ssh (
  $base_packages = hiera_array("${module_name}::base_packages", []),
) {
  validate_array($base_packages)
  ensure_packages($base_packages)
}
