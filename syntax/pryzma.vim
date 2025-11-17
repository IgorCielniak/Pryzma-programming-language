
" Check if syntax is already loaded
if exists("b:current_syntax")
  finish
endif

" Keywords
syntax keyword pryzmaKeyword print input #preproc #insert struct foreach for if while pyeval pyexec exec eval isolate try int str loc  assert use from copy append pop remove sys file_write delvar delfunc disablekeyword enablekeyword move swap call ccall load wait push dpop defer return mkdir makedirs rmdir removedirs copyfile rename remove_path symlink unlink match write patch json_dump using read new_isolate replace json_load resplit in splitby type len splitlines file_read index all isanumber dirname startswith endswith randint strip get char join defined is_file is_dir exists file_size join_path abs_path basename split_ext list_dir walk is_link read_link fields is_func ascii #fd #np #nan #an #fail #df #rs #rds #esc #desc #gc #ngc #replace global timenow else break catch stop list with as
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

