project('dpdk_pot', 'c')

dep_dpdk = dependency('libdpdk', required: true)
openssl_dep = dependency('openssl', required: true)

inc = include_directories('include')

# Grab C files from project root
root_src = files('main.c')

# Run the script to grab .c files under src/
grabber = run_command('./make/scripts/grabber.sh', check: true)
src_files = grabber.stdout().strip().split('\n')

all_sources = root_src + src_files

executable('dpdk-pot',
  all_sources,
  dependencies: [dep_dpdk, openssl_dep],
  include_directories: inc
)