from secret_vault import SecretVault
import hashlib
import os
import re
import sys

try:
    sv = SecretVault('127.0.0.1:3333', './api_key.key')

except Exception as e:
    print(e)
    exit(1)


regex_rvalue = '''\s*[\S]+\s*=\s*([\S]+)\s*'''
regex_assign = '''\s*[\S]+\s*=\s*['"]([\S]+)['"]\s*'''
regex_param = '''([^\s\)]+)\((.+?)\)(?=[^()]*(\(|$))?'''
regex_return = '''return\s+['"](\S+)['"]'''
def checker(path):
    filename = path
    line_count = 0
    unsafe = False
    with open(filename, 'r') as f:
        content = f.readlines()
        for l in content:
            line_count += 1
            data = []
            # print(f'[*] Parsing line: {line_count}')
            if l == '\n':
                continue
            
            line = l.strip()
            
            assign = re.match(regex_assign, line)
            if assign:
                for d in assign.groups(2):
                    if d == '':
                        continue
                    data.append(d)

            parma = re.match(regex_param, line)
            if parma:
                for d in parma.groups(1):
                    if d == '':
                        continue
                    data.append(d)

            ret = re.match(regex_return, line)
            if ret:
                for d in ret.groups(1):
                    if d == '':
                        continue
                    data.append(d)

            for d in data:
                all_string = d.split(',')
                for s in all_string:
                    fin = s.replace('"', '').replace('\'', '').replace(' ', '')

                    h = hashlib.sha256(fin.encode()).hexdigest()

                    if sv.check_is_expose(h, filename, line_count):
                        unsafe = True
                        print(f'[-] Secret EXPOSED IN SOURCE at line: {line_count} in {filename}')

    return False if unsafe else True        

path = './'
all_paths = []
for root, dirs, files in os.walk(path):
    for f in files:
        if '.pyc' in f or f in 'secret_vault' or f == '__init__.py':
            continue

        full_path = (os.path.join(root, f))
        full_path = full_path.replace('\\', '/')
        all_paths.append(full_path)

for path in all_paths:
    print(f'[*] Now checking file: {path}')
    
    if checker(path):
        print(f'[+] Good!')

    else:
        print(f'[-] FOUND SECRET LEAK IN FILE: {path}')
