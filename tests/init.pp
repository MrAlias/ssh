# The base ssh class is not intended to be called directly.
# Howerver, in order to ensure smoke test coverage this is added
class { 'ssh':
  base_packages => ['test', 'packages'],
}
