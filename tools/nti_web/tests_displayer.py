#!/usr/bin/env python3

import sys, os, glob, re, subprocess

### Argument parsing

if len(sys.argv) != 2:
    print("Usage: %s <path>" % (sys.argv[0]))
    sys.exit(1)

path = sys.argv[1]

out_file = "/var/www/html/gen/tests_displayer.html"

# Code
tests = set()

npath = os.path.normpath(path) + '/'
all_files = glob.glob(npath + '*')
dir_regex = re.compile(npath + '(.*)_\d{4}-\d{2}-\d{2}_\d{2}:\d{2}')

for f in all_files:
    # Skip files and dirs which don't have correct names
    m = dir_regex.match(f)
    if not m:
        continue

    # single_config.py will process all results for the config, only call once
    test = m.groups()[0]
    if test in tests:
        continue
    tests.add(test)

    upos = test.find('_')
    kind = test[:upos]
    conf = test[upos + 1:]

    print("Running for", kind, conf)
    subprocess.run("python3 " + os.path.dirname(sys.argv[0]) + "/single_config.py %s %s %s" %
                   (npath, conf, kind), shell=True, check=True)

test_row = '''
<div id="div{id}" onclick="buttonClick({id})" class="options">
    {name}
</div>
<br>
'''
i = 0
html_text = ""
for test in sorted(tests):
    html_text += test_row.format(id=i, name=test)
    i += 1

script_tbl = ''
for test in sorted(tests):
    script_tbl += '"' + test + '.html", '
script_tbl += '"done"'

tmpl = open(os.path.dirname(sys.argv[0]) + '/displayer_tmpl.html', 'r')
out = open(out_file, "w")
for line in tmpl:
    if line.count("<!-- X_CONTENT_X -->"):
        out.write(html_text)
    elif line.count("<!-- X_SCRIPT_TBL_X -->"):
        out.write(script_tbl)
    else:
        out.write(line)
out.close()
tmpl.close()
