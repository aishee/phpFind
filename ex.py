import fnmatch
import glob
import sys
import os
import time

try:
    import yara
except ImportError:
    print("Please install yara: python-yara")
    sys.exit(0)
if len(sys.argv) != 2 :
    print('Usage: %s folder_to_scan' % sys.argv[0])
rule = yara.compile('malwares.yara')
for cpt, (root, dirnames, filenames) in enumerate(os.walk(sys.argv[1])):
    for filename in fnmatch.filter(filenames, "*.ph*"):
        if not cpt % 1000:
            time.sleep(3)
        fname = os.path.join(root, filename)
        if os.stat(fname).st_size:
                matches = rule.match(os.path.join(root, filename), fast=True)
                if matches:
                    matches = matches.pop()
                    print(str(matches) + fname)
                    print('\n'.join(hex(m[0]) + ':' + m[1] + ':' + m[2] for m in matches.strings))