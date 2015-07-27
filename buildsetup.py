import sys
from cx_Freeze import setup, Executable

#sys.path.append('sbu_scripts/')
#sys.path.append('lib/')

binincludes = ['distorm3.dll']
binpaths = ['.']
#includefiles = [('lib/libcrypto.so.1.0.0','lib/libcrypto.so.1.0.0'),]
includefiles = [('plugins'),
                (r'C:\Tools\Work\Work\Qiew\distorm3.dll', 'distorm3.dll')]

exe = Executable(
    script="qiew.py",
    )

setup(
    name = "Qiew",
    version = "1.1",
    description = "Binary/Hex format viewer",
    # , 'packages':["distorm3"]
    options = {"build_exe": {'copy_dependent_files':True, 'create_shared_zip':False, 'bin_includes':binincludes, 'bin_path_includes':binpaths, 'include_files':includefiles}},
    executables = [exe]
    )
