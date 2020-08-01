from secret_vault import SecretVault
import sys
import re
import hashlib

if len(sys.argv) < 2:
    print(f'Usage: {__file__} <file_name>')
    sys.exit(1)

try:
    sv = SecretVault('127.0.0.1:3333', './api_key.key')

except Exception as e:
    print(e)
    exit(1)


# sv.check_is_expose('af9a3f83109c82a62fc28e85668d5323efc0947b5e2cde80d2b1007ded7b2')
regex_rvalue = '''\s*[\S]+\s*=\s*([\S]+)\s*'''
regex_assign = '''\s*[\S]+\s*=\s*['"]([\S]+)['"]\s*'''
regex_param = '''([^\s\)]+)\((.+?)\)(?=[^()]*(\(|$))?'''
regex_return = '''return\s+['"](\S+)['"]'''

filename = sys.argv[1]
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

                if sv.check_is_expose(h, sys.argv[1], line_count):
                    unsafe = True
                    print(f'[-] Error!! Secret EXPOSED IN SOURCE at line: {line_count}')

if unsafe:
    print('[-] Unsafe secret found! Please resolve the problem.')

else:
    print('[+] Everything is GOOD!')