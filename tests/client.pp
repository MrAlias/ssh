class { 'ssh::client':
  package_name    => 'test_client_ssh_package_name',
  manage_firewall => false,
}
