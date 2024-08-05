project('qemu-plugins', 'c', meson_version: '>=0.54.0')

qemu_src = get_option('qemu_path')
if qemu_src == ''
  qemu_src = '../qemu'
endif

qemu_include = qemu_src + '/include/qemu'
incdir = include_directories(qemu_include)

plugins = [
  'tcgmmu'
]

th = dependency('threads', required: true)
glib = dependency('glib-2.0', required: true)
#libdwarf_addr2line = dependency('libdwarf-addr2line', required: true)

foreach p: plugins
  library(p, p + '.c',
    include_directories: incdir,
     dependencies: [th, glib, libdwarf_addr2line],
     override_options: ['b_lundef=false']
)
endforeach
