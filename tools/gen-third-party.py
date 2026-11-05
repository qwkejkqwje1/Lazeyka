#!/usr/bin/env python3
"""Собирает THIRD-PARTY.txt: шапка (dist/THIRD-PARTY.head.txt) + все Rust-пакеты,
которые входят в lazeyka.exe для заданной цели, с текстами их лицензий.
Пакеты группируются по одинаковому тексту лицензии (как в cargo-about).

    python3 tools/gen-third-party.py x86_64-pc-windows-gnullvm OUT.txt
"""
import collections, hashlib, json, os, re, subprocess, sys

target, out_path = sys.argv[1], sys.argv[2]
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OWN = {'lazeyka', 'lazeyka-core'}

tree = subprocess.run(
    ['cargo', 'tree', '--offline', '--target', target, '-e', 'normal', '--prefix', 'none',
     '-f', '{p}|{l}', '-p', 'lazeyka'],
    cwd=root, check=True, capture_output=True, text=True).stdout
meta = json.loads(subprocess.run(
    ['cargo', 'metadata', '--offline', '--format-version', '1', '--filter-platform', target],
    cwd=root, check=True, capture_output=True, text=True).stdout)
dirs = {(p['name'], p['version']): os.path.dirname(p['manifest_path']) for p in meta['packages']}

crates = {}
for line in tree.splitlines():
    if '|' not in line:
        continue
    pkg, lic = line.split('|', 1)
    parts = pkg.split(' ')
    name, ver = parts[0], parts[1].lstrip('v')
    if name not in OWN:
        crates[(name, ver)] = lic.strip() or 'см. файл лицензии пакета'
crates = sorted(crates.items())

LIC_FILE = re.compile(r'^(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICENSE)', re.I)
def norm(t):
    return re.sub(r'\s+', ' ', t).strip()

groups = collections.OrderedDict()  # key -> [text, [crates]]
missing = []
for (name, ver), lic in crates:
    d = dirs.get((name, ver), '')
    files = []
    if os.path.isdir(d):
        files = [os.path.join(d, f) for f in sorted(os.listdir(d))
                 if LIC_FILE.match(f) and os.path.isfile(os.path.join(d, f))]
        ld = os.path.join(d, 'LICENSES')
        if os.path.isdir(ld):
            files += [os.path.join(ld, f) for f in sorted(os.listdir(ld))]
    texts = []
    for fp in files:
        t = open(fp, encoding='utf-8', errors='replace').read().strip('\n')
        if len(t.strip()) >= 40:
            texts.append(t)
    if not texts:
        missing.append(f'{name} {ver} ({lic})')
        continue
    for t in texts:
        nt = norm(t)
        if 'Apache License' in nt[:300] and 'Version 2.0, January 2004' in nt[:400] and 'TERMS AND CONDITIONS' in nt:
            key = 'apache-2.0'  # все варианты текста Apache-2.0 равнозначны: приводим один
        else:
            key = hashlib.sha1(nt.encode()).hexdigest()
        g = groups.setdefault(key, [t, []])
        if f'{name} {ver}' not in g[1]:
            g[1].append(f'{name} {ver}')

head = open(os.path.join(root, 'dist', 'THIRD-PARTY.head.txt'), encoding='utf-8').read().rstrip('\n')
o = [head, '', f'Всего пакетов: {len(crates)}', '']
o += [f'  {n} {v} — {l}' for (n, v), l in crates]
if missing:
    o += ['', 'Пакеты без отдельного файла лицензии (действует лицензия из манифеста пакета):']
    o += [f'  {m}' for m in missing]
o += ['', 'Тексты лицензий. Каждый текст приведён один раз вместе с перечнем пакетов,', 'к которым он относится.']
for t, lst in groups.values():
    o += ['', '-' * 78, 'Пакеты: ' + ', '.join(lst), '-' * 78, t]
text = '\n'.join(o) + '\n'
with open(out_path, 'w', encoding='utf-8-sig', newline='\r\n') as f:
    f.write(text)
print(f'{out_path}: пакетов {len(crates)}, текстов лицензий {len(groups)}, без файла {len(missing)}', file=sys.stderr)
