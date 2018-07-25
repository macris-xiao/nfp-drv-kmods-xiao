#!/usr/bin/env python3

import os, sys, gzip, html

### Argument parsing

indent = 2
path = sys.argv[1]

test_run = path.split('/')[len(path.split('/')) - 2]
out_file = "/var/www/html/gen/" + test_run + ".html.gz"

# Code
if os.path.exists(out_file):
    sys.exit(0)
print("  Formatting logs for: " + test_run)

html_text = ""

divCounter = 0
with open(path, "r", encoding='utf-8', errors='ignore') as fp:
    starParser = list()
    secondStarParser = list()

    lastCount = 0
    noStarToggler = 0
    preStars = 1

    for line in fp:
        starCounter = 0
        while line[starCounter] == '*':
            starCounter += 1

        if starCounter > 0:
            preStars = 0
            if noStarToggler == 1:
                noStarToggler = 0
                html_text += '</div>'
            if lastCount > starCounter:
                html_text += '</div>'

            html_text += '<div id="div' + str(divCounter) +'" style="margin-left:'
            if starCounter > 1:
                html_text += str(indent * (starCounter - 1)) + 'em; display:none">'
            else:
                html_text += '0em; display:block">'

            divCounter += 1

            starParser.append(str(starCounter))
            secondStarParser.append(starCounter)

            lastCount = starCounter
        else:
            if noStarToggler == 0:
                noStarToggler = 1
                if preStars == 1:
                    display = 'block'
                else:
                    display = 'none'

                html_text += '</div><div id="div' + str(divCounter) + '" style="margin-left:' + str(indent * lastCount) + 'em; display:' + display + '; background-color: #ddd; color: black">'

                divCounter += 1

                starParser.append(str(lastCount+1))
                secondStarParser.append(starCounter)
                lastCount = starCounter

        html_text += html.escape(line[starCounter:], quote=True)
        html_text += "<br>\n"

    html_text += "</div>"

script_tbl = ""
for  i in range(len(starParser)):
    script_tbl += str(starParser[i]) + ', '

listener = '''
document.getElementById("div{i}").addEventListener("click",
function() {{
    divHider("div{i}");
}}
);
'''
script_listeners = ""
for i in range(0, divCounter):
    if secondStarParser[i] > 0:
        script_listeners += listener.format(i=i)

tmpl = open(os.path.dirname(sys.argv[0]) + '/details_displayer_tmpl.html', 'r')
out = gzip.GzipFile(out_file, 'wb')
for line in tmpl:
    line = line.replace('<!-- X_TITLE_X -->', test_run)
    if line.count("<!-- X_CONTENT_X -->"):
        line = html_text
    elif line.count("<!-- X_SCRIPT_TBL_X -->"):
        line = script_tbl
    elif line.count("<!-- X_SCRIPT_LISTENERS_X -->"):
        line = script_listeners

    out.write(line.encode('utf-8'))
out.close()
