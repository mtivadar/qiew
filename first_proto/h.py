import os

data = []
for i in range(256):
    data += [chr(i)]

print data
open('bb', 'w+').write(''.join(data))