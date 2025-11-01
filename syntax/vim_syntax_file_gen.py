with open("Pryzma.py") as f:
    orig_content = f.read()

content = orig_content.splitlines()

for i in range(0, len(content)):
    content[i] = content[i].strip()

pragmas = []

for line in content:
    if line.startswith('if "') and line.endswith('" in args:'):
        pragmas.append(f"#{line[4:-10]}")

pragmas.append("#replace")

filtered = []

for i, line in enumerate(content):
    if line.startswith("if line.startswith") or line.startswith("if expression.startswith") or line.startswith("elif line.startswith") or line.startswith("elif expression.startswith"):
        filtered.append([i+1, line])

seen = set()
filtered2 = []

for num, s in filtered:
    if s not in seen:
        filtered2.append([num, s])
        seen.add(s)

filtered = filtered2

new = []

for i in range(0, len(filtered)):
    if not filtered[i][1].startswith("if line.startswith(stmt.strip())"):
        new.append(filtered[i])

filtered = new

for i in range(0, len(filtered)):
    if filtered[i][1].startswith("if line.startswith"):
        filtered[i][1] = filtered[i][1][20:]
    elif filtered[i][1].startswith("elif line.startswith"):
        filtered[i][1] = filtered[i][1][22:]
    elif filtered[i][1].startswith("if expression.startswith"):
        filtered[i][1] = filtered[i][1][26:]
    elif filtered[i][1].startswith("elif expression.startswith"):
        filtered[i][1] = filtered[i][1][28:]

for i in range(0, len(filtered)):
    if " and " in filtered[i][1]:
        filtered[i][1] = filtered[i][1].split(" and ")[0].strip()

for i in range(0, len(filtered)):
    if filtered[i][1].endswith('"):'):
        filtered[i][1] = filtered[i][1][:-3]
    elif filtered[i][1].endswith('")'):
        filtered[i][1] = filtered[i][1][:-2]

for i in range(0, len(filtered)):
    filtered[i][1] = filtered[i][1][:-1] if filtered[i][1].endswith("(") else filtered[i][1][:-1] if filtered[i][1].endswith("{") else filtered[i][1]

seen = set()
filtered2 = []

for num, s in filtered:
    if s not in seen:
        filtered2.append([num, s])
        seen.add(s)

filtered = filtered2

new = []

for i in range(0, len(filtered)):
    if len(filtered[i][1]) > 1 and not filtered[i][1].startswith("/"):
        new.append(filtered[i])

filtered = new

final = [elem[1] for elem in filtered] + pragmas

final.append("global")
final.append("timenow")
final.append("else")
final.append("break")
final.append("catch")
final.append("stop")
final.append("list")
final.append("with")
final.append("as")

template = rf"""
" Check if syntax is already loaded
if exists("b:current_syntax")
  finish
endif

" Keywords
syntax keyword pryzmaKeyword {" ".join([keyword for keyword in final])}
syntax keyword pryzmaBoolean True False None

" Operators
syntax match pryzmaOperator "++\|--\|=\|==\|!=\|<\|<=\|>\|>="

" Strings
syntax match pryzmaString /"[^"]*"/ contains=NONE

" Numbers (integers and floats)
syntax match pryzmaNumber "\<[0-9]\+\(\.[0-9]\+\)\?\>"

" Comments
syntax match pryzmaComment "//.*$"

" Highlight groups
highlight link pryzmaKeyword Keyword
highlight link pryzmaBoolean Boolean
highlight link pryzmaOperator Operator
highlight link pryzmaString String
highlight link pryzmaNumber Number
highlight link pryzmaComment Comment

let b:current_syntax = "pryzma"
"""

print(template)
