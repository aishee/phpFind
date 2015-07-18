import fnmatch
import hashlib
import os
import sys

try:
    import yara
except ImportError:
    print("Please install yara: python-yara")
    sys.exit(0)
if len(sys.argv) !=3:
    print('Usage: %s name_of_the_rule_and_version folder_to_scan' % sys.argv[0])
rules = yara.compile('./malwares.yara', includes=True, error_on_warning=True)
output_list = list()
for cpt,(root, dirnames, filenames) in enumerate(os.walk(sys.argv[2])):
    for filename in fnmatch.filter(filenames, '*.ph*'):
        fname = os.path.join(root, filename)
        if os.stat(fname).st_size:
            matches = rules.matches(os.path.join(root, filename), fast=True)
            if matches:
                matches = matches.pop()
                output_list.append('hash.sha1(0,filename) == %s or // %s' %(hashlib.sha1(fname).hexdigest(), fname))
output_rule = 'private rule %s\n{\n\tcondition:\n\t\t/* %s */\n\t\t' % (sys.argv[1].split(' ')[0], sys.argv[1])
output_list.append(output_list.pop().replace(' or ', '    '))
output_rule += '\n\t\t'.join(output_list)
output_rule +='\n}'
print(output_rule)