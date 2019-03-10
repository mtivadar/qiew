import sys, os

import PyInstaller.__main__

qiew = 'qiew'
buildcmd = [
    '--name=%s' % qiew,
#    '--onefile',
    '--console',
#    '--add-binary=%s' % os.path.join('plugins', '*.*', ),
    '--add-data={};{}'.format(os.path.join('plugins','format','pe.py'), os.path.join('plugins','format')), 
]

def add_datas(buildcmd, path, allowed=['.py', '.ui', '.yapsy-plugin', '.disabled']):
    L = os.listdir(path)
    for l in L:
        name, extension = os.path.splitext(l)
        if extension in allowed:
            datas = '--add-data={};{}'.format(os.path.join(path, l), path)
            buildcmd += [datas]
            print(datas)

    


add_datas(buildcmd, os.path.join('plugins', 'format'))
add_datas(buildcmd, os.path.join('plugins', 'unpack'))
add_datas(buildcmd, os.path.join('.'), allowed=['.ui'])

bin = '--add-data={};{}'.format(r'C:\Python36\Lib\site-packages\capstone\capstone.dll', '.')

buildcmd += [bin]

L = os.listdir('.')
for l in L:
    name, extension = os.path.splitext(l)
    if extension in ['.py']:
        buildcmd += [os.path.join(l)]

buildcmd += [os.path.join('qiew.py')]

PyInstaller.__main__.run(
buildcmd)
