project('ssh-pairing', 'c',
        license: 'GPL-2.0-or-later',
        version: '0.1')

executable('ssh-pairing-server',
           'ssh-pairing-server.c',
           dependencies: dependency('libssh'),
           install: true,
           install_dir: get_option('sbindir'))

install_data('ssh-pairing',
             install_mode: 'rwxr-xr-x',
             install_dir: get_option('sbindir'))
