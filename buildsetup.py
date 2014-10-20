import sys
from cx_Freeze import setup, Executable

#sys.path.append('sbu_scripts/')
#sys.path.append('lib/')

binincludes = ['distorm3.dll']
binpaths = ['.']
#includefiles = [('lib/libcrypto.so.1.0.0','lib/libcrypto.so.1.0.0'),]
includefiles = [('plugins')]

exe = Executable(
    script="qiew.py",
    )

setup(
    name = "Qiew",
    version = "0.1",
    description = "Binary/Hex format viewer",
    options = {"build_exe": {'copy_dependent_files':True, 'create_shared_zip':True, 'bin_includes':binincludes, 'bin_path_includes':binpaths, 'include_files':includefiles, 'packages':["distorm3"]}},
    executables = [exe]
    )
