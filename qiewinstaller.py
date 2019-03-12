import sys, os

import PyInstaller.__main__

qiew = 'qiew'
buildcmd = [
    '--name=%s' % qiew,
    '--onefile',
    '--console',
]

def add_datas(buildcmd, path, allowed=['.py', '.ui', '.yapsy-plugin', '.disabled']):
    L = os.listdir(path)
    for l in L:
        name, extension = os.path.splitext(l)
        if extension in allowed:
            datas = '--add-data={};{}'.format(os.path.join(path, l), path)
            buildcmd += [datas]
            print(datas)

         
# plugins
add_datas(buildcmd, os.path.join('plugins', 'format'))
add_datas(buildcmd, os.path.join('plugins', 'unpack'))
add_datas(buildcmd, os.path.join('.'), allowed=['.ui'])

# capstone
bin = '--add-data={};{}'.format(r'C:\Python36\Lib\site-packages\capstone\capstone.dll', '.')
buildcmd += [bin]

# modules
#bin = '--hidden-import={}'.format('elftools')
#buildcmd += [bin]

# scripts
L = os.listdir('.')
for l in L:
    name, extension = os.path.splitext(l)
    if extension in ['.py']:
        buildcmd += [os.path.join(l)]

# scripts
L = os.listdir(os.path.join('.', 'plugins', 'format'))
for l in L:
    name, extension = os.path.splitext(l)
    if extension in ['.py']:
        buildcmd += [os.path.join('plugins', 'format', l)]


buildcmd += [os.path.join('qiew.py')]

PyInstaller.__main__.run(
buildcmd)
