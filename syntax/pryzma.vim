"this syntax file is made for an older version of pryzma but still
"provides some highlight today, i may update it in the furure

" Check if syntax is already loaded
if exists("b:current_syntax")
  finish
endif

" Keywords
syntax keyword pryzmaKeyword if else for foreach while break return try catch
syntax keyword pryzmaKeyword defer match stop int str loc struct use from load
syntax keyword pryzmaKeyword call ccall pyeval pyexec exec delfunc file_read
syntax keyword pryzmaKeyword file_write mkdir makedirs rmdir removedirs copy
syntax keyword pryzmaKeyword copyfile move rename remove symlink unlink is_file
syntax keyword pryzmaKeyword is_dir exists file_size join_path abs_path basename
syntax keyword pryzmaKeyword split_ext list_dir walk is_link read_link append
syntax keyword pryzmaKeyword pop remove move swap push dpop get fields len
syntax keyword pryzmaKeyword splitlines all join index type isanumber char
syntax keyword pryzmaKeyword ascii strip splitby resplit replace in defined
syntax keyword pryzmaKeyword sys wait timenow print input assert delvar
syntax keyword pryzmaKeyword disablekeyword enablekeyword asm py read write
syntax keyword pryzmaKeyword randint startswith endswith is_func
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

