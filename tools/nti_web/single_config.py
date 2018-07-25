#!/usr/bin/env python3

import os, sys, webbrowser, glob, subprocess

### Argument parsing

if len(sys.argv) != 4:
    print("Usage: %s <path> <configs> <test_name>" % (sys.argv[0]))
    sys.exit(1)

path = sys.argv[1]
configs = sys.argv[2]
test_name = sys.argv[3]

file_pfx = test_name + '_' + configs
tests = 'tests.' + test_name
out_file = "/var/www/html/gen/" + file_pfx + ".html"

### Code

# Parse all results into dict of dicts
# { "date" : { "test1" : result, "test2" : result,  etc. } etc. }
dictio = {}

search_path = os.path.join(path, file_pfx) + "_*"
print("Looking for files in " + search_path)
for dirName in glob.glob(search_path):
    testResults = {}
    testDate = dirName.split(file_pfx + "_")[1]
    summaryFile = os.path.join(dirName, "summary.log")

    cmd = "python3 %s/details_displayer.py %s/details.log" % \
        (os.path.dirname(sys.argv[0]), dirName)
    subprocess.run(cmd, shell=True, check=True)

    with open(summaryFile, "r") as summary:
        for line in summary:
            cols = line.split(":")
            result = cols[1].strip()
            arr = cols[0].split(tests + ".")
            if len(arr) > 1:
                test = arr[1].strip()
                if test != "Test Summary" and test != "":
                    testResults[test] = result

    dictio[testDate] = testResults

# Find all the tests
tableHeaders = set()
for key, value in dictio.items():
    tableHeaders |= value.keys()
tableHeaders = list(tableHeaders)
tableHeaders.sort()

# Calculate header height
th_height = 0
firstIsMax = 0
for header in tableHeaders:
    if len(header) > th_height:
        th_height = len(header)

if th_height > len(configs + "/" + tests):
    th_height *= 0.6
else:
    th_height = len(configs + "/" + tests) * 0.6

html_text = ""

hdr  = '<div class="div-cell rotate" style="height:{height}em; width:{width}em;">'
hdr += '<div style="bottom:0; transform:translateY({transY}em) rotate(270deg)">'
hdr += "{text}</div></div>"

html_text += hdr.format(height=th_height, width=9,
                        transY=th_height * 0.6, text=configs + "/" + tests)

for header in tableHeaders:
    html_text += hdr.format(height=th_height, width="1.2",
                            transY=th_height * 0.9, text=header)

html_text += '</div>'

cell = '<div class="div-cell" style="background-color:{color}; width:1.2em">&nbsp;</div>'

items = sorted(dictio.items())
items.reverse()
for key, value in items:
    if not value:
        continue
    html_text += '<div class="div-tr"><div class="div-cell" style="width:9em">'
    html_text += '<a href="{w}_{k}.html.gz">{k}</a>'.format(k=key, w=file_pfx)
    html_text += '</div>'
    for header in tableHeaders:
        if header in value:
            result = value[header].split()[0]
            if result == "passed":
                html_text += cell.format(color="green")
            elif result == "FAILED":
                html_text += cell.format(color="red")
            elif result == "SKIP":
                html_text += cell.format(color="#ffffbb")
            else:
                html_text += cell.format(color="black")
        else:
            html_text+='<div class="div-cell" style="width:1.2em">&nbsp;</div>'
    html_text += '</div>'

tmpl = open(os.path.dirname(sys.argv[0]) + '/single_config_tmpl.html', 'r')
out = open(out_file, "w")
for line in tmpl:
    if line.count("<!-- X_CONTENT_X -->"):
        out.write(html_text)
    else:
        out.write(line)
out.close()
tmpl.close()
