import sys, os
from cx_Freeze import setup, Executable

QIEW_VER = '1.1'
#sys.path.append('sbu_scripts/')
#sys.path.append('lib/')

binincludes = [r'capstone.dll ']
binpaths = ['.', r'C:\Python27\Lib\site-packages\capstone']
#includefiles = [('lib/libcrypto.so.1.0.0','lib/libcrypto.so.1.0.0'),]
includefiles = [(r'plugins'), (r'search.ui'), ('DisasmViewMode.py')]
#                (r'capstone.dll')]

build_exe_options = {
                     "build_exe": {
                        'copy_dependent_files':True,    
                        'create_shared_zip':False, 
                        'bin_path_includes':binpaths, 
                        'bin_includes':binincludes, 
                        'include_files':includefiles,
                        "packages" : ["elftools", "androguard"],
                        "build_exe" : os.path.join('build', 'qiew-v{0}-win-amd64-2.7'.format(QIEW_VER)),
                        "optimize" : 2
                    }
}
exe = Executable(
    script="qiew.py",
    )

setup(
    name = "Qiew",
    version = QIEW_VER,
    description = "Binary/Hex format viewer",
    options = build_exe_options,
    executables = [exe]
    )
