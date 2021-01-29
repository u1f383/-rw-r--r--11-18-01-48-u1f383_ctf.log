#!/usr/bin/python

import subprocess


while True:
    p = subprocess.Popen(['strings', 'gift'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    out = out.split('\n')
    t = ''
    for s in out:
        if len(s) == 256:
            t = s
    if t == '':
        break
    print(t)
    p0 = subprocess.Popen(['chmod', '+x', 'gift'], stdout=subprocess.PIPE)
    p1 = subprocess.Popen(['echo', t], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(['./gift'], stdin=p1.stdout, stdout=subprocess.PIPE)
    out, err = p2.communicate()
    open('gift.gz', 'wb').write(out)
    p3 = subprocess.Popen(['gunzip', '-f', 'gift.gz'], stdout=subprocess.PIPE)
