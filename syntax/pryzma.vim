"this syntax file is made for an older version of pryzma but still
"provides some highlight today, i may update it in the furure

" Check if syntax is already loaded
if exists("b:current_syntax")
  finish
endif

" Keywords
syntax keyword pryzmaKeyword if for while whilen print input use copy append pop
syntax keyword pryzmaKeyword exec write delvar delfunc move swap tk call replace
syntax keyword pryzmaKeyword interpret_pryzma stop type len splitby split splitlines
syntax keyword pryzmaKeyword read in index all isanumber dir timenow
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

