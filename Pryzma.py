import re
import sys
import os
import importlib.util
import time
import datetime
import json
import shutil
import zipfile
import platform
import random


class PryzmaInterpreter:
    
    def __init__(self):
        self.variables = {}
        self.functions = {}
        self.tk_vars = {}
        self.custom_handlers = {}
        self.deleted_key_words = []
        self.variables["interpreter_path"] = __file__
        self.variables["err"] = 0
        self.in_try_block = False
        self.in_func = False
        self.current_func_name = None
        self.preprocess_only = False
        self.no_preproc = False
        self.forward_declare = False
        self.nan = False
        self.return_val = None
        self.break_stack = []

    def interpret_file(self, file_path, *args):
        self.file_path = file_path.strip('"')
        self.variables["argv"] = args
        self.variables["__file__"] = os.path.abspath(file_path)
        try:
            with open(self.file_path, 'r') as file:
                program = file.read()
                self.interpret(program)
        except FileNotFoundError:
            print(f"File '{self.file_path}' not found.")

    def interpret(self, program):
        program = program.splitlines()
        for line in range(0,len(program)-1):
            program[line] = program[line].split("#")[0]
        program = ";".join(program)

        self.no_preproc = False

        first_line = program.split(";")[0]

        if first_line.startswith("preproc"):
            preproc_line = first_line
            if "=" in preproc_line:
                args = preproc_line.split("=")[1].split(",")
                for arg in range(0,len(args)):
                    args[arg] = args[arg].strip()
                if "fd" in args:
                    self.forward_declare = True
                if "np" in args:
                    self.no_preproc = True
                if "nan" in args:
                    self.nan = True

        if not self.no_preproc:
            rep_in_func = 0
            char_ = 0
            prog = list(program)
            for char in prog:
                if char == "{":
                    rep_in_func += 1
                elif char == "}":
                    rep_in_func -= 1
                elif rep_in_func != 0  and char == ";":
                    prog[char_] = "|"
                char_ += 1
            prog2 = ""
            for char in prog:
                prog2+=char
            program = prog2

        if not self.in_func:
            self.current_line = 0

        lines = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', program)
        lines = [stmt.strip() for stmt in lines if stmt.strip()]

        if self.preprocess_only == True:
            for line in lines:
                print(line)
            sys.exit()

        if self.forward_declare == True:
            self.forward_declare = False
            for line in lines:
                if line.startswith("/"):
                    self.interpret(line)
                    lines.remove(line)


        for line in lines:
            self.current_line += 1
            line = line.strip()

            if line == "" or line.startswith("#") or line.startswith("preproc"):
                continue
            if "#" in line:
                line = line.split("#")[0]

            deleted_keyword = False

            for key_word in self.deleted_key_words:
                if line.startswith(key_word):
                    keyword = key_word
                    deleted_keyword = True

            if deleted_keyword:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 1
                    print(f"Error near line {self.current_line}: keyword deleted '{keyword}'")
                else:
                    self.variables["err"] = 1
                continue

            handled = False
            for handler in self.custom_handlers.values():
                if handler(self, line):
                    handled = True
                    break

            if handled:
                continue

            try:
                if line.startswith("print"):
                    value = line[len("print"):].strip()
                    self.print_value(value)
                elif line.startswith("input"):
                    variable = line[len("input"):].strip()
                    self.custom_input(variable)
                elif line.startswith("foreach"):
                    line = line[7:].strip()
                    args, action = line.strip()[1:-1].split("){", 1)
                    char_ = 0
                    rep_in_for = 0
                    for_body = list(action)
                    for char in for_body:
                        if char == "{":
                            rep_in_for += 1
                        elif char == "}":
                            rep_in_for -= 1
                        elif rep_in_for == 0  and char == "|":
                            for_body[char_] = "&$"
                        char_ += 1

                    for_body2 = ""
                    for char in for_body:
                        for_body2 += char
                    actions = for_body2.split("&$")
                    loop_var, list_name = args.split(",")
                    loop_var = loop_var.strip()
                    list_name = list_name.strip()
                    for action in actions:
                        action = action.strip()

                    self.break_stack.append(False)

                    if list_name in self.variables:
                        for val in self.variables[list_name]:
                            self.variables[loop_var] = val
                            for action in actions:
                                self.interpret(action)
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 41
                            print(f"Error near line {self.current_line}: Invalid range expression for loop.")
                        else:
                            self.variables["err"] = 41

                    self.break_stack.pop()
                elif line.startswith("for"):
                    line = line[3:].strip()
                    range_expr, action = line.strip()[1:-1].split("){", 1)
                    char_ = 0
                    rep_in_for = 0
                    for_body = list(action)
                    for char in for_body:
                        if char == "{":
                            rep_in_for += 1
                        elif char == "}":
                            rep_in_for -= 1
                        elif rep_in_for == 0  and char == "|":
                            for_body[char_] = "&$"
                        char_ += 1

                    for_body2 = ""
                    for char in for_body:
                        for_body2 += char
                    actions = for_body2.split("&$")
                    loop_var, range_expr = range_expr.split(",")
                    loop_var = loop_var.strip()
                    range_expr = range_expr.strip()
                    for action in actions:
                        action = action.strip()
                    self.for_loop(loop_var, range_expr, actions)
                elif line.startswith("use"):
                    file_path = line[3:].strip()
                    self.import_functions(file_path)
                elif line.startswith("if"):
                    else_ = False
                    if "else" in line:
                        else_ = True
                        sline = line.split("else")
                        line = sline[0]
                        else_part = sline[1]
                    line = line[2:]
                    condition, action = line.strip()[1:-1].split("){", 1)
                    handeled = False
                    char_ = 0
                    rep_in_if = 0
                    if_body = list(action)
                    for char in if_body:
                        if char == "{":
                            rep_in_if += 1
                        elif char == "}":
                            rep_in_if -= 1
                        elif rep_in_if == 0  and char == "|":
                            if_body[char_] = "&$"
                        char_ += 1
                    if_body2 = ""
                    for char in if_body:
                        if_body2 += char
                    actions = if_body2.split("&$")
                    if "==" in condition:
                        value1 = self.evaluate_expression(condition.split("==")[0])
                        value2 = self.evaluate_expression(condition.split("==")[1])
                        if value1 == value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif "!=" in condition:
                        value1 = self.evaluate_expression(condition.split("!=")[0])
                        value2 = self.evaluate_expression(condition.split("!=")[1])
                        if value1 != value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif "<=" in condition:
                        value1 = self.evaluate_expression(condition.split("<=")[0])
                        value2 = self.evaluate_expression(condition.split("<=")[1])
                        if value1 <= value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif ">=" in condition:
                        value1 = self.evaluate_expression(condition.split(">=")[0])
                        value2 = self.evaluate_expression(condition.split(">=")[1])
                        if value1 >= value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif "<" in condition:
                        value1 = self.evaluate_expression(condition.split("<")[0])
                        value2 = self.evaluate_expression(condition.split("<")[1])
                        if value1 < value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif ">" in condition:
                        value1 = self.evaluate_expression(condition.split(">")[0])
                        value2 = self.evaluate_expression(condition.split(">")[1])
                        if value1 > value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    else:
                        value = self.evaluate_expression(condition)
                        if value:
                            handeled = True
                            for action in actions:
                                self.interpret(action)

                    if handeled == False and else_:
                        char_ = 0
                        rep_in_if = 0
                        body = list(else_part[1:-1])
                        for char in body:
                            if char == "{":
                                rep_in_if += 1
                            elif char == "}":
                                rep_in_if -= 1
                            elif rep_in_if == 0  and char == "|":
                                body[char_] = "&$"
                            char_ += 1
                        body2 = ""
                        for char in body:
                            body2 += char
                        actions = body2.split("&$")
                        for action in actions:
                            self.interpret(action)
                elif line.startswith("while"):
                    line = line[5:]
                    condition, action = line.strip()[1:-1].split("){", 1)
                    char_ = 0
                    rep_in_if = 0
                    if_body = list(action)
                    for char in if_body:
                        if char == "{":
                            rep_in_if += 1
                        elif char == "}":
                            rep_in_if -= 1
                        elif rep_in_if == 0  and char == "|":
                            if_body[char_] = "%$"
                        char_ += 1
                    if_body2 = ""
                    for char in if_body:
                        if_body2 += char
                    self.break_ = False
                    actions = if_body2.split("%$")
                    if "==" in condition:
                        value1 = self.evaluate_expression(condition.split("==")[0])
                        value2 = self.evaluate_expression(condition.split("==")[1])
                        self.break_stack.append(False)
                        while value1 == value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("==")[0])
                                value2 = self.evaluate_expression(condition.split("==")[1])
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif "!=" in condition:
                        value1 = self.evaluate_expression(condition.split("!=")[0])
                        value2 = self.evaluate_expression(condition.split("!=")[1])
                        self.break_stack.append(False)
                        while value1 != value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("!=")[0])
                                value2 = self.evaluate_expression(condition.split("!=")[1])
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif "<=" in condition:
                        value1 = self.evaluate_expression(condition.split("<=")[0])
                        value2 = self.evaluate_expression(condition.split("<=")[1])
                        self.break_stack.append(False)
                        while value1 <= value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("<=")[0])
                                value2 = self.evaluate_expression(condition.split("<=")[1])
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif ">=" in condition:
                        value1 = self.evaluate_expression(condition.split(">=")[0])
                        value2 = self.evaluate_expression(condition.split(">=")[1])
                        self.break_stack.append(False)
                        while value1 >= value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split(">=")[0])
                                value2 = self.evaluate_expression(condition.split(">=")[1])
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif "<" in condition:
                        value1 = self.evaluate_expression(condition.split("<")[0])
                        value2 = self.evaluate_expression(condition.split("<")[1])
                        self.break_stack.append(False)
                        while value1 < value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("<")[0])
                                value2 = self.evaluate_expression(condition.split("<")[1])
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif ">" in condition:
                        value1 = self.evaluate_expression(condition.split(">")[0])
                        value2 = self.evaluate_expression(condition.split(">")[1])
                        self.break_stack.append(False)
                        while value1 > value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split(">")[0])
                                value2 = self.evaluate_expression(condition.split(">")[1])
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    else:
                        value = self.evaluate_expression(condition)
                        self.break_stack.append(False)
                        while value:
                            for action in actions:
                                self.interpret(action)
                                value = self.evaluate_expression(condition)
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                elif line.startswith("/"):
                    function_definition = line[1:].split("{", 1)
                    if len(function_definition) == 2:
                        function_name = function_definition[0].strip()
                        function_body = function_definition[1].strip()[:-1]
                        char_ = 0
                        rep_in_func = 0
                        function_body = list(function_body)
                        for char in function_body:
                            if char == "{":
                                rep_in_func += 1
                            elif char == "}":
                                rep_in_func -= 1
                            elif rep_in_func == 0  and char == "|":
                                function_body[char_] = "&$"
                            char_ += 1
                        function_body2 = ""
                        for char in function_body:
                            function_body2 += char
                        function_body = function_body2.split("&$")
                        self.functions[function_name] = function_body
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 2
                            print(f"Invalid function definition at line {self.current_line}")
                        else:
                            self.variables["err"] = 2
                elif line.startswith("@"):
                    self.in_func = True
                    function_name = line[1:].strip()
                    if "(" in function_name:
                        function_name, arg = function_name.split("(")
                        self.current_func_name = function_name
                        arg = arg.strip(")")
                        if arg:
                            arg = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', arg)
                            for args in range(len(arg)):
                                arg[args] = self.evaluate_expression(arg[args].strip())
                            self.variables["args"] = arg
                    self.current_func_name = function_name
                    if function_name in self.functions:
                        command = 0
                        while command < len(self.functions[function_name]):
                            self.interpret(self.functions[function_name][command])
                            command += 1
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 3
                            print(f"Error near line {self.current_line}: Function '{function_name}' is not defined.")
                        else:
                            self.variables["err"] = 3
                    self.in_func = False
                    self.current_func_name = None
                elif line.startswith("eval(") and line.endswith(")"):
                    code = line[5:-1]
                    if "|" in code:
                        code = code.split("|")
                        for part in code:
                            self.interpret(self.evaluate_expression(part))
                    else:
                        self.interpret(self.evaluate_expression(code))
                elif line.startswith("try{") and line.endswith("}"):
                    self.in_try_block = True
                    instructions = line[4:-1].split("|")
                    error = 0
                    for instruction in instructions:
                        self.interpret(instruction)
                        if self.variables["err"] != 0:
                            error = self.variables["err"]
                    self.variables["err"] = error
                    self.in_try_block = False
                elif "+=" in line:
                    line = line.split("+=")
                    if len(line) != 2:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 4
                            print(f"Error near line {self.current_line}: Too much arguments")
                        else:
                            self.variables["err"] = 4
                        continue
                    var = line[0].strip()
                    var2 = line[1].strip()
                    var2 = self.evaluate_expression(var2)
                    self.variables[var] += var2
                elif "-=" in line:
                    line = line.split("-=")
                    if len(line) != 2:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 5
                            print(f"Error near line {self.current_line}: Too much arguments")
                        else:
                            self.variables["err"] = 5
                        continue
                    var = line[0].strip()
                    var2 = line[1].strip()
                    var2 = self.evaluate_expression(var2)
                    self.variables[var] -= var2
                elif line.startswith("int"):
                    line = line[3:].strip()
                    if "=" in line:
                        variable, expression = line.split("=", 1)
                        variable = variable.strip()
                        expression = expression.strip()
                        self.variables[variable] = int(self.evaluate_expression(expression))
                    else:
                        variable = line.strip()
                        self.variables[line] = 0
                elif line.startswith("str"):
                    line = line[3:].strip()
                    if "=" in line:
                        variable, expression = line.split("=", 1)
                        variable = variable.strip()
                        expression = expression.strip()
                        self.variables[variable] = str(self.evaluate_expression(expression))
                    else:
                        variable = line.strip()
                        self.variables[line] = ""
                elif "=" in line:
                    variable, expression = line.split('=', 1)
                    variable = variable.strip()
                    expression = expression.strip()
                    if "][" in variable:
                        variable, indexes = variable.split("[",1)
                        indexes = indexes[:-1].split("][")
                        index1 = self.evaluate_expression(indexes[0])
                        index2 = self.evaluate_expression(indexes[1])
                        self.variables[variable][index1][index2] = self.evaluate_expression(expression)
                    elif "[" in variable and "]" in variable:
                        variable, index = variable[:-1].split("[",1)
                        self.variables[variable][self.evaluate_expression(index)] = self.evaluate_expression(expression)
                    else:
                        self.variables[variable] = self.evaluate_expression(expression)
                elif line.startswith("copy"):
                    list1, list2 = line[4:].split(",")
                    list1 = list1.strip()
                    list2 = list2.strip()
                    for element in self.variables[list1]:
                        self.variables[list2].append(element)
                elif line.startswith("append"):
                    list_name, value = line[6:].split(",")
                    list_name = list_name.strip()
                    value = value.strip()
                    self.append_to_list(list_name, value)
                elif line.startswith("pop"):
                    list_name, index = line[3:].split(",")
                    list_name = list_name.strip()
                    index = index.strip()
                    self.pop_from_list(list_name, index)
                elif line.startswith("remove"):
                    list_name, var = line[6:].split(",")
                    list_name = list_name.strip()
                    var = var.strip()
                    self.variables[list_name].remove(self.evaluate_expression(var))
                elif line.startswith("exec"):
                    os.system(self.evaluate_expression(line[4:]))
                elif line.startswith("write(") and line.endswith(")"):
                    line = line[6:-1].split(",")
                    if len(line) == 3:
                        file_path = self.evaluate_expression(line[0].strip())
                        mode = self.evaluate_expression(line[1].strip())
                        content = self.evaluate_expression(line[2].strip())
                        self.write_to_file(file_path, mode, str(content))
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 6
                            print(f"Error near line {self.current_line}: Invalid number of arguments for write()")
                        else:
                            self.variables["err"] = 6
                elif line.startswith("delvar(") and line.endswith(")"):
                    self.variables.pop(self.evaluate_expression(line[7:-1]))
                elif line.startswith("delfunc(") and line.endswith(")"):
                    self.functions.pop(self.evaluate_expression(line[8:-1]))
                elif line.startswith("delkeyword(") and line.endswith(")"):
                    self.deleted_key_words.append(self.evaluate_expression(line[11:-1]))
                elif "++" in line:
                    variable = line.replace("++", "").strip()
                    self.increment_variable(variable)
                elif "--" in line:
                    variable = line.replace("--", "").strip()
                    self.decrement_variable(variable)
                elif line.startswith("move(") and line.endswith(")"):
                    instructions = line[5:-1].split(",")
                    if len(instructions) != 3:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 7
                            print(f"Error near line {self.current_line}: Invalid move instruction syntax. Expected format: move(old index, new index, list name)")
                        else:
                            self.variables["err"] = 7
                        continue
                    list_name = instructions[2].strip()
                    try:
                        old_index = int(instructions[0])
                        new_index = int(instructions[1])
                        value = self.variables[list_name].pop(old_index)
                        self.variables[list_name].insert(new_index, value)
                    except ValueError:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 8
                            print(f"Error near line {self.current_line}: Invalid index")
                        else:
                            self.variables["err"] = 8
                elif line.startswith("swap(") and line.endswith(")"):
                    instructions = line[5:-1].split(",")
                    if len(instructions) != 3:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 9
                            print(f"Error near line {self.current_line}: Invalid swap instruction syntax. Expected format: swap(index 1, index 2, list name)")
                        else:
                            self.variables["err"] = 9
                        continue
                    list_name = instructions[2].strip()
                    try:
                        index_1 = int(self.evaluate_expression(instructions[0].strip()))
                        index_2 = int(self.evaluate_expression(instructions[1].strip()))
                        self.variables[list_name][index_1], self.variables[list_name][index_2] = self.variables[list_name][index_2], self.variables[list_name][index_1]
                    except ValueError:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 10
                            print("Invalid index fir swap()")
                        else:
                            self.variables["err"] = 10
                elif line.startswith("tk"):
                    global tkinter_enabled
                    command = line[2:].strip()
                    if command.strip().startswith("enable"):
                        tkinter_enabled = True
                    elif tkinter_enabled == True:
                        import tkinter as tk
                        if command.startswith("window(") and command.endswith(")"):
                            command = command[7:-1]
                            self.tk_vars[command] = tk.Tk()
                        elif command.startswith("title(") and command.endswith(")"):
                            command = command[6:-1]
                            command = command.split(",")
                            window = command[0].lstrip()
                            title = command[1].lstrip()
                            if title.startswith('"') and title.endswith('"'):
                                title = title[1:-1]
                            else:
                                title = self.variables[title]
                            self.tk_vars[window].title(title)
                        elif command.startswith("mainloop(") and command.endswith(")"):
                            command = command[9:-1]
                            self.tk_vars[command].mainloop()
                        elif command.startswith("create_button(") and command.endswith(")"):
                            command = command[14:-1]
                            command = command.split(",")
                            window = command[1].lstrip()
                            button_name = command[0].lstrip()
                            button_text = command[2].lstrip()
                            button_text = button_text.lstrip()
                            button_command = command[3].lstrip()
                            if button_text.startswith('"') and button_text.endswith('"'):
                                button_text = button_text[1:-1]
                            else:
                                button_text = self.variables[button_text]
                            if len(command) == 2:
                                self.tk_vars[button_name] = tk.Button(self.tk_vars[window])
                            elif len(command) == 3:
                                self.tk_vars[button_name] = tk.Button(self.tk_vars[window],text = button_text)
                            elif len(command) == 4:
                                self.tk_vars[button_name] = tk.Button(self.tk_vars[window],text = button_text,command = lambda: self.interpret(button_command))
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 11
                                    print(f"Error near line {self.current_line}: Invalid create_button command")
                                else:
                                    self.variables["err"] = 11
                            self.tk_vars[button_name].pack()
                        elif command.startswith("create_label(") and command.endswith(")"):
                            command = command[13:-1]
                            command = command.split(",")
                            window = command[1].lstrip()
                            label_name = command[0].lstrip()
                            label_text = command[2].lstrip()
                            label_text = label_text.lstrip()
                            if label_text.startswith('"') and label_text.endswith('"'):
                                label_text = label_text[1:-1]
                            else:
                                label_text = self.variables[label_text]
                            if len(command) == 2:
                                self.tk_vars[label_name] = tk.Label(self.tk_vars[window])
                            elif len(command) == 3:
                                self.tk_vars[label_name] = tk.Label(self.tk_vars[window],text = label_text)
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 12
                                    print(f"Error near line {self.current_line}: Invalid create_label command")
                                else:
                                    self.variables["err"] = 12
                            self.tk_vars[label_name].pack()
                        elif command.startswith("create_entry(") and command.endswith(")"):
                            command = command[13:-1]
                            command = command.split(",")
                            window = command[1].lstrip()
                            entry_name = command[0].lstrip()
                            entry_text = command[2].lstrip()
                            entry_text = entry_text.lstrip()
                            if entry_text.startswith('"') and entry_text.endswith('"'):
                                entry_text = entry_text[1:-1]
                            else:
                                entry_text = self.variables[entry_text]
                            if len(command) == 2:
                                self.tk_vars[entry_name] = tk.Entry(self.tk_vars[window])
                            elif len(command) == 3:
                                self.tk_vars[entry_name] = tk.Entry(self.tk_vars[window],text = entry_text)
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 13
                                    print(f"Error near line {self.current_line}: Invalid create_entry command")
                                else:
                                    self.variables["err"] = 13
                            self.tk_vars[entry_name].pack()
                        elif command.startswith("get_entry_text(") and command.endswith(")"):
                            command = command[15:-1]
                            command = command.split(",")
                            entry_name = command[0].lstrip()
                            variable_name = command[1].lstrip()
                            if entry_name in self.tk_vars:
                                self.variables[variable_name] = self.tk_vars[entry_name].get()
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 14
                                    print(f"Error near line {self.current_line}: Invalid get_entry_text command")
                                else:
                                    self.variables["err"] = 14
                        elif command.startswith("set_entry_text(") and command.endswith(")"):
                            command = command[15:-1]
                            command = command.split(",")
                            entry_name = command[0].lstrip()
                            variable_name = command[1].lstrip()
                            if entry_name in self.tk_vars:
                                self.tk_vars[entry_name].delete(0, tk.END)
                                self.tk_vars[entry_name].insert(0, self.variables[variable_name])
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 15
                                    print(f"Error near line {self.current_line}: Invalid set_entry_text command")
                                else:
                                    self.variables["err"] = 15
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 16
                            print(f"Error near line {self.current_line}: tkinter isn't enabled")
                        else:
                            self.variables["err"] = 16
                elif line.startswith("call"):
                    call_statement = line[4:].strip()
                    file_name, function_name, args = self.parse_call_statement(call_statement)
                    self.call_function_from_file(file_name, function_name, args)
                elif line.startswith("load(") and line.endswith(")"):
                    self.load_module(self.evaluate_expression(line[5:-1]))
                elif line.startswith("wait(") and line.endswith(")"):
                    time_to_wait = float(line[5:-1])
                    time.sleep(time_to_wait)
                elif line.startswith("push(") and line.endswith(")"):
                    dict_name, key, value = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[5:-1])
                    key = self.evaluate_expression(key)
                    value = self.evaluate_expression(value)
                    self.variables[dict_name][key] = value
                elif line.startswith("dpop(") and line.endswith(")"):
                    dict_name, key = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[5:-1])
                    key = self.evaluate_expression(key)
                    self.variables[dict_name].pop(key)
                elif line.startswith("return"):
                    self.ret_val = self.evaluate_expression(line[6:])
                elif line == "break":
                    self.break_stack[-1] = True
                elif line.startswith("asm{") and line.endswith("}"):
                    try:
                        asm_emulator = X86Emulator()
                    except ImportError:
                        asm_emulator = None
                        print("ERROR: x86 emulation not available (probably missing keystone/unicorn)")
                        continue
                    line = line[4:-1]
                    code = line.split("|")
                    code = list(filter(None, code))
                    for line in range(len(code)):
                        code[line] = self.evaluate_expression(code[line].strip())
                    code = "asm{\n"+"\n".join(code)+"\n}"
                    asm_vars = {}
                    for i in self.variables:
                        if type(self.variables[i]) == int:
                            asm_vars[i] = self.variables[i]
                    if asm_emulator:
                        try:
                            results = asm_emulator.run(code, asm_vars)
                            for var, val in results.items():
                                self.variables[var] = val
                        except Exception as e:
                            print(f"ASM emulation error: {e}")
                    else:
                        print("ASM emulation not available")
                elif line.startswith("py{") and line.endswith("}"):
                    line = line[3:-1]
                    code = line.split("|")
                    code = list(filter(None, code))
                    for line in range(len(code)):
                        code[line] = self.evaluate_expression(code[line].strip())
                    exec(";".join(code), {}, self.variables)
                elif line.startswith("mkdir(") and line.endswith(")"):
                    path = self.evaluate_expression(line[6:-1])
                    os.mkdir(path)
                elif line.startswith("makedirs(") and line.endswith(")"):
                    path = self.evaluate_expression(line[9:-1])
                    os.makedirs(path, exist_ok=True)
                elif line.startswith("rmdir(") and line.endswith(")"):
                    path = self.evaluate_expression(line[6:-1])
                    os.rmdir(path)
                elif line.startswith("removedirs(") and line.endswith(")"):
                    path = self.evaluate_expression(line[11:-1])
                    os.removedirs(path)
                elif line.startswith("copy(") and line.endswith(")"):
                    args = self.evaluate_expression(line[5:-1]).split(',')
                    src = args[0].strip()
                    dst = args[1].strip()
                    shutil.copy(src, dst)
                elif line.startswith("copyfile(") and line.endswith(")"):
                    args = self.evaluate_expression(line[9:-1]).split(',')
                    src = args[0].strip()
                    dst = args[1].strip()
                    shutil.copyfile(src, dst)
                elif line.startswith("move(") and line.endswith(")"):
                    args = self.evaluate_expression(line[5:-1]).split(',')
                    src = args[0].strip()
                    dst = args[1].strip()
                    shutil.move(src, dst)
                elif line.startswith("rename(") and line.endswith(")"):
                    args = self.evaluate_expression(line[7:-1]).split(',')
                    src = args[0].strip()
                    dst = args[1].strip()
                    os.rename(src, dst)
                elif line.startswith("remove(") and line.endswith(")"):
                    path = self.evaluate_expression(line[7:-1])
                    os.remove(path)
                elif line.startswith("symlink(") and line.endswith(")"):
                    args = self.evaluate_expression(line[8:-1]).split(',')
                    src = args[0].strip()
                    dst = args[1].strip()
                    os.symlink(src, dst)
                elif line.startswith("unlink(") and line.endswith(")"):
                    path = self.evaluate_expression(line[7:-1])
                    os.unlink(path)
                elif line.startswith("match(") and "{" in line:
                    line = line[6:-1]
                    var, cases = line.split("){", 1)
                    var = self.evaluate_expression(var.strip())

                    processed_cases = ""
                    depth = 0

                    for char in list(cases):
                        if char == "{":
                            processed_cases += char
                            depth += 1
                        elif char == "}":
                            processed_cases += char
                            depth -= 1
                        elif depth == 1 and char == "|":
                            processed_cases += "&@"
                        else:
                            processed_cases += char

                    cases = processed_cases.split("|")
                    cases = list(filter(None, cases))

                    default_case = None
                    handeled = False

                    for case in cases:
                        case = case.strip()
                        case = case[5:-1].split("){")
                        value = self.evaluate_expression(case[0]) if case[0] != "_" else "_"
                        if value == "_":
                            default_case = case
                            continue
                        if var == value:
                            handeled = True
                            for instruction in case[1].split("&@"):
                                self.interpret(instruction)

                    if handeled == False and default_case:
                        for instruction in default_case[1].split("&@"):
                            self.interpret(instruction)
                elif line == "stop":
                    sys.exit()
                else:
                    if not handled:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 17
                            print(f"Invalid statement at line {self.current_line}: {line}")
                        else:
                            self.variables["err"] = 17

            except Exception as e:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 18
                    print(f"Error near line {self.current_line}: {e}")
                else:
                    self.variables["err"] = 18

    def in_func_err(self):
        if self.in_func:
            print(f"Error while calling function '{self.current_func_name}'")

    def load_module(self, module_path):
        try:
            module_name = os.path.basename(module_path).replace(".py", "")
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "start"):
                self.custom_handlers[module_name] = module.start
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 19
                    print(f"Module '{module_name}' does not have a 'start' function.")
                else:
                    self.variables["err"] = 19
        except Exception as e:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 20
                print(f"Error loading module '{module_path}': {e}")
            else:
                self.variables["err"] = 20

    def decrement_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int):
                self.variables[variable] -= 1
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 21
                    print(f"Error near line {self.current_line}: Cannot decrement non-integer variable '{variable}'.")
                else:
                    self.variables["err"] = 21
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 22
                print(f"Error near line {self.current_line}: Variable '{variable}' not found.")
            else:
                self.variables["err"] = 22

    def increment_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int):
                self.variables[variable] += 1
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 23
                    print(f"Error near line {self.current_line}: Cannot increment non-integer variable '{variable}'.")
                else:
                    self.variables["err"] = 23
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 24
                print(f"Error near line {self.current_line}: Variable '{variable}' not found.")
            else:
                self.variables["err"] = 24


    def write_to_file(self, file_path, mode, content):
        try:
            with open(file_path, mode) as file:
                if isinstance(content, list):
                    for line in content:
                        file.write(f"{line}\n")
                else:
                    file.write(content)
        except Exception as e:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 25
                print(f"Error near line {self.current_line} while writing to file '{file_path}': {e}")
            else:
                self.variables["err"] = 25

    def evaluate_expression(self, expression):
        if re.match(r"^\d+$", expression):
            return int(expression)
        elif expression.startswith("pyeval(") and expression.endswith(")"):
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[7:-1])
            if len(parts) == 1:
                return eval(self.evaluate_expression(parts[0]))
            else:
                return eval(self.evaluate_expression(parts[0]),self.evaluate_expression(parts[1]))
        elif expression.startswith("replace(") and expression.endswith(")"):
            expression = expression[8:-1]
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression)
            if len(parts) != 3:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 26
                    print(f"Error near line {self.current_line}: Invalid number of arguments for replace function.")
                else:
                    self.variables["err"] = 26
                    return None
            value = self.evaluate_expression(parts[0].strip())
            old = self.evaluate_expression(parts[1].strip())
            new = self.evaluate_expression(parts[2].strip())
            if old == "\\n":
                old = "\n"
            if new == "\\n":
               new = "\n"
            return value.replace(old,new)
        elif re.match(r'^".*"$', expression):
            return expression[1:-1]
        elif expression.startswith("resplit(") and expression.endswith(")"):
            args = expression[8:-1].strip()
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', args)
            if len(parts) != 2:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 27
                    print(f"Error near line {self.current_line}: Invalid number of arguments for resplit(). Expected 2 arguments.")
                else:
                    self.variables["err"] = 27
                return None
    
            regex_pattern = self.evaluate_expression(parts[0].strip())
            string_to_split = self.evaluate_expression(parts[1].strip())
    
            if not isinstance(regex_pattern, str):
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 28
                    print(f"Error near line {self.current_line}: The first argument of resplit() must be a string (regex pattern).")
                else:
                    self.variables["err"] = 28
                return None
            regex_pattern = r"{}".format(regex_pattern) 
            if not isinstance(string_to_split, str):
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 29
                    print(f"Error near line {self.current_line}: The second argument of resplit() must be a string.")
                else:
                    self.variables["err"] = 29
                return None
    
            try:
                return re.split(regex_pattern, string_to_split)
            except re.error as e:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 30
                    print(f"Error near line {self.current_line}: Invalid regex pattern: {e}")
                else:
                    self.variables["err"] = 30
                return None
        elif expression.startswith("in(") and expression.endswith(")"):
            value1, value2 = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[3:-1])
            value1 = self.evaluate_expression(value1.strip())
            value2 = self.evaluate_expression(value2.strip())
            try:
                return value2 in value1
            except Exception as e:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 31
                    print(f"in() function error near line {self.current_line}: {e}")
                else:
                    self.variables["err"] = 31
        elif expression.startswith("splitby(") and expression.endswith(")"):
            args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[8:-1])
            if len(args) < 2:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 32
                    print(f"Error near line {self.current_line}: Invalid number of arguments for splitby function.")
                else:
                    self.variables["err"] = 32
                return None
            char_to_split = self.evaluate_expression(args[0].strip())
            string_to_split = self.evaluate_expression(args[1].strip())
            if len(args) == 3:
                return string_to_split.split(char_to_split,self.evaluate_expression(args[2]))
            else:
                return string_to_split.split(char_to_split)
        elif "+" in expression:
            parts = expression.split("+")
            evaluated_parts = [self.evaluate_expression(part.strip()) for part in parts]
            if all(isinstance(part, str) for part in evaluated_parts):
                return "".join(evaluated_parts)
            elif all(isinstance(part, (int)) for part in evaluated_parts):
                return sum(int(part) for part in evaluated_parts)
            elif all(isinstance(part, (float)) for part in evaluated_parts):
                return sum(float(part) for part in evaluated_parts)
            elif any(isinstance(part, str) for part in evaluated_parts) and any(isinstance(part, (int, float)) for part in evaluated_parts): 
                for parts in evaluated_parts:
                    if type(parts) == int:
                        evaluated_parts = [str(item) for item in evaluated_parts]
                return "".join(evaluated_parts)
            elif all(isinstance(part, list) for part in evaluated_parts):
                return sum(evaluated_parts, [])
            elif all(isinstance(part, tuple) for part in evaluated_parts):
                return sum(evaluated_parts ,())
        elif "=" in expression:
            var, val = expression.split("=")
            var = var.strip()
            val = val.strip()
            if var.startswith("int(") and var.endswith(")"):
                if self.var in self.variables:
                    return int(self.variables[var])
                return int(self.evaluate_expression(val))
            elif var.startswith("str(") and var.endswith(")"):
                if self.var in self.variables:
                    return str(self.variables[var])
                return str(self.evaluate_expression(val))
            else:
                return self.evaluate_expression(val)
        elif expression.startswith("type(") and expression.endswith(")"):
            return str(type(self.variables[expression[5:-1]]).__name__)
        elif expression.startswith("len(") and expression.endswith(")"):
            value = expression[4:-1]
            if "[" in value and "]" in value:
                value,index = value[:-1].split("[")
                index = self.evaluate_expression(index)
                return len(self.variables[value[index]])
            return len(self.variables[value])
        elif expression.startswith("split(") and expression.endswith(")"):
            expression = expression[6:-1]
            if expression in self.variables:
                expression = self.variables[expression]
            if expression.startswith('"') and expression.endswith('"'):
                expression = expression[1:-1]
            return list(expression)
        elif expression.startswith("splitlines(") and expression.endswith(")"):
            return self.variables[expression[11:-1]].splitlines()
        elif expression.startswith("read(") and expression.endswith(")"):
            file_path = self.evaluate_expression(expression[5:-1])
            try:
                with open(file_path, 'r') as file:
                    return file.read()
            except FileNotFoundError:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 33
                    print(f"Error near line {self.current_line}: File '{file_path}' not found.")
                else:
                    self.variables["err"] = 33
                return ""
        elif expression.startswith("index(") and expression.endswith(")"):
            args = expression[6:-1].split(",")
            if len(args) != 2:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 34
                    print(f"Error near line {self.current_line}: Invalid number of arguments for index function.")
                else:
                    self.variables["err"] = 34
                return None
            list_name = args[0].strip()
            value = args[1].strip()
            if list_name in self.variables and isinstance(self.variables[list_name], list):
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                else:
                    if value in self.variables:
                        value = self.variables[value]
                    else:
                        value = int(value)
                try:
                    index_value = self.variables[list_name].index(value)
                    return index_value
                except ValueError:
                    if not self.in_try_block:
                        self.in_func_err()
                        self.variables["err"] = 35
                        print(f"Error near line {self.current_line}: Value '{value}' not found in list '{list_name}'.")
                    else:
                        self.variables["err"] = 35
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 36
                    print(f"Error near line {self.current_line}: Variable '{list_name}' is not a list.")
                else:
                    self.variables["err"] = 36
        elif expression.startswith("all(") and expression.endswith(")"):
            list_name = expression[4:-1]
            if list_name in self.variables and isinstance(self.variables[list_name], list):
                return "".join(map(str, self.variables[list_name]))
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 37
                    print(f"Error near line {self.current_line}: List '{list_name}' is not defined.")
                else:
                    self.variables["err"] = 37
                return None
        elif expression.startswith("isanumber(") and expression.endswith(")"):
            expression = expression[10:-1]
            if expression in self.variables:
                expression = self.variables[expression]
                return str(expression).isnumeric()
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 38
                    print(f"Error near line {self.current_line}: Variable '{expression}' is not defined.")
                else:
                    self.variables["err"] = 38
                return None
        elif expression.startswith("dirname(") and expression.endswith(")"):
            expression = expression[8:-1]
            if expression.startswith('"') and expression.endswith('"'):
                return os.path.dirname(expression[1:-1])
            elif expression in self.variables:
                return os.path.dirname(self.variables[expression])
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 39
                    print(f"Error near line {self.current_line}: Invalid argument for dirname() function")
                else:
                    self.variables["err"] = 39
                return None
        elif expression == "timenow":
            return datetime.datetime.now()
        elif expression.startswith("startswith(") and expression.endswith(")"):
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[11:-1])
            return self.evaluate_expression(parts[1]).startswith(self.evaluate_expression(parts[0]))
        elif expression.startswith("endswith(") and expression.endswith(")"):
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[11:-1])
            return self.evaluate_expression(parts[1]).endsswith(self.evaluate_expression(parts[0]))
        elif expression.startswith("randint(") and expression.endswith(")"):
            range_ = expression[8:-1]
            range_ = range_.split(",")
            return random.randint(self.evaluate_expression(range_[0]), self.evaluate_expression(range_[1]))
        elif expression.startswith("strip(") and expression.endswith(")"):
            return self.evaluate_expression(expression[6:-1]).strip()
        elif expression.startswith("get(") and expression.endswith(")"):
            dict_name, key = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[4:-1])
            key = self.evaluate_expression(key)
            return self.variables[dict_name][key]
        elif expression.startswith("@"):
            self.ret_val = None
            self.interpret(expression)
            return self.ret_val
        elif expression.startswith("char(") and expression.endswith(")"):
            return chr(self.evaluate_expression(expression[5:-1]))
        elif expression.startswith("join(") and expression.endswith(")"):
            char, value = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[5:-1])
            char = self.evaluate_expression(char)
            value = self.evaluate_expression(value)
            return char.join(value)
        elif expression.startswith("defined(") and expression.endswith(")"):
            return expression[8:-1] in self.variables
        elif expression.startswith("is_file(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[8:-1])
            return os.path.isfile(path)
        elif expression.startswith("is_dir(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[7:-1])
            return os.path.isdir(path)
        elif expression.startswith("exists(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[7:-1])
            return os.path.exists(path)
        elif expression.startswith("file_size(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[10:-1])
            return os.path.getsize(path)
        elif expression.startswith("join_path(") and expression.endswith(")"):
            args = self.evaluate_expression(line[10:-1]).split(',')
            paths = [p.strip() for p in args]
            return os.path.join(*paths)
        elif expression.startswith("abs_path(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[9:-1])
            return os.path.abspath(path)
        elif expression.startswith("basename(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[9:-1])
            return os.path.basename(path)
        elif expression.startswith("split_ext(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[10:-1])
            return os.path.splitext(path)
        elif expression.startswith("list_dir(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[9:-1])
            return os.listdir(path)
        elif expression.startswith("walk(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[5:-1])
            return list(os.walk(path))
        elif expression.startswith("is_link(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[8:-1])
            return os.path.islink(path)
        elif expression.startswith("read_link(") and expression.endswith(")"):
            path = self.evaluate_expression(expression[10:-1])
            return os.readlink(path)
        elif expression in self.variables:
            return self.variables[expression]
        else:
            try:
                return eval(expression, {}, self.variables)
            except NameError:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 40
                    print(f"Error near line {self.current_line}: Unknown variable or expression: {expression}")
                else:
                    self.variables["err"] = 40
        return None

    def print_value(self, value):
        parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', value)
        part_count = 0
        for part in parts:
            parts[part_count] = self.evaluate_expression(parts[part_count])
            if isinstance(parts[part_count], str):
                parts[part_count] = parts[part_count].replace("\\n", "\n")
            part_count += 1
        for part in parts:
            print(part, end="")

    def custom_input(self, variable):
        if "::" in variable:
            variable_name, prompt = variable.split("::", 1)
            variable_name = variable_name.strip()
            prompt = prompt.strip('"')
        else:
            variable_name = variable.strip()
            prompt = ""

        value = self.get_input(prompt)
        self.variables[variable_name] = value


    def for_loop(self, loop_var, range_expr, actions):
        start, end = range_expr.split(":")
        start_val = self.evaluate_expression(start)
        end_val = self.evaluate_expression(end)

        self.break_stack.append(False)

        if isinstance(start_val, int) and isinstance(end_val, int):
            for val in range(start_val, end_val):
                self.variables[loop_var] = val
                for action in actions:
                    self.interpret(action)
                    if self.break_stack[-1]:
                        break
                if self.break_stack[-1]:
                    break
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 41
                print(f"Error near line {self.current_line}: Invalid range expression for loop.")
            else:
                self.variables["err"] = 41

        self.break_stack.pop()

    def import_functions(self, file_path):
        file_path = file_path.strip('"')
    
        if file_path.startswith("https://") or file_path.startswith("http://"):
            import requests
            name = os.path.basename(file_path).split(".")[0]
            f = requests.get(file_path)
            program = f.text
            program = program.splitlines()
            for line in range(0,len(program)-1):
                program[line] = program[line].split("#")[0]
            program = ";".join(program)

            self.no_preproc = False

            first_line = program.split(";")[0]

            if first_line.startswith("preproc"):
                preproc_line = first_line
                if "=" in preproc_line:
                    args = preproc_line.split("=")[1].split(",")
                    for arg in range(0,len(args)):
                        args[arg] = args[arg].strip()
                    if "np" in args:
                        self.no_preproc = True

            if not self.no_preproc:
                rep_in_func = 0
                char_ = 0
                prog = list(program)
                for char in prog:
                    if char == "{":
                        rep_in_func += 1
                    elif char == "}":
                        rep_in_func -= 1
                    elif rep_in_func != 0  and char == ";":
                        prog[char_] = "|"
                    char_ += 1
                prog2 = ""
                for char in prog:
                    prog2+=char
                program = prog2

            lines = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', program)
            lines = [stmt.strip() for stmt in lines if stmt.strip()]

            function_def = False
            function_name = ""
            function_body = []
            for line in lines:
                if line.startswith("/"):
                    if not self.nan:
                        if line[1:].startswith(name+"."):
                            line = "/" + line[1:]
                        else:
                            line = "/" + name + "."  + line[1:]
                    self.interpret(line)
                    if not self.nan:
                        if line.startswith("/"+name+".on_import"):
                            self.interpret("@"+name+".on_import")
                    else:
                        if line.startswith("/on_import"):
                            self.interpret("@on_import")
        elif '/' in file_path or '\\' in file_path:
            self.load_functions_from_file(file_path)
        else:
            file_path = f"{PackageManager.user_packages_path}/{file_path}/{file_path}.pryzma"
            self.load_functions_from_file(file_path)

    def load_functions_from_file(self, file_path):
        name = os.path.splitext(os.path.basename(file_path))[0]
        try:
            with open(file_path, 'r') as file:
                program = file.read()
                program = program.splitlines()
                for line in range(0,len(program)-1):
                    program[line] = program[line].split("#")[0]
                program = ";".join(program)

                self.no_preproc = False

                first_line = program.split(";")[0]

                if first_line.startswith("preproc"):
                    preproc_line = first_line
                    if "=" in preproc_line:
                        args = preproc_line.split("=")[1].split(",")
                        for arg in range(0,len(args)):
                            args[arg] = args[arg].strip()
                        if "np" in args:
                            self.no_preproc = True

                if not self.no_preproc:
                    rep_in_func = 0
                    char_ = 0
                    prog = list(program)
                    for char in prog:
                        if char == "{":
                            rep_in_func += 1
                        elif char == "}":
                            rep_in_func -= 1
                        elif rep_in_func != 0  and char == ";":
                            prog[char_] = "|"
                        char_ += 1
                    prog2 = ""
                    for char in prog:
                        prog2+=char
                    program = prog2

                lines = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', program)
                lines = [stmt.strip() for stmt in lines if stmt.strip()]

                function_def = False
                function_name = ""
                function_body = []
                for line in lines:
                    if line.startswith("/"):
                        if not self.nan:
                            if line[1:].startswith(name+"."):
                                line = "/" + line[1:]
                            else:
                                line = "/" + name + "."  + line[1:]
                        self.interpret(line)
                        if not self.nan:
                            if line.startswith("/"+name+".on_import"):
                                self.interpret("@"+name+".on_import")
                        else:
                            if line.startswith("/on_import"):
                                self.interpret("@on_import")
        except FileNotFoundError:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 42
                print(f"Error near line {self.current_line}: File '{file_path}' not found.")
            else:
                self.variables["err"] = 42

    def get_input(self, prompt):
        if sys.stdin.isatty():
            return input(prompt)
        else:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            return sys.stdin.readline().rstrip('\n')

    def interpret_file2(self):
        self.file_path = input("Enter the file path of the program: ")
        self.interpret_file(self.file_path)

    def show_license(self):
        license_text = """
Pryzma
Copyright 2025 Igor Cielniak

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
        """

        print(license_text)
    
    def append_to_list(self, list_name, value):
        if "[" in list_name:
            list_name, index = list_name[:-1].split("[")
            self.variables[list_name][self.evaluate_expression(index)].append(self.evaluate_expression(value))
        elif list_name in self.variables:
            self.variables[list_name].append(self.evaluate_expression(value))
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 43
                print(f"Error near line {self.current_line}: List '{list_name}' does not exist.")
            else:
                self.variables["err"] = 43

    def pop_from_list(self, list_name, index):
        if list_name in self.variables:
            try:
                if index.isnumeric():
                    index = int(index)
                else:
                    index = self.variables[index]
                self.variables[list_name].pop(index)
            except IndexError:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 44
                    print(f"Error near line {self.current_line}: Index {index} out of range for list '{list_name}'.")
                else:
                    self.variables["err"] = 44
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 45
                print(f"Error near line {self.current_line}: List '{list_name}' does not exist.")
            else:
                self.variables["err"] = 45


    def execute_function_from_file(self):
        file_path = input("Enter the file path of the function: ")
        function_name = input("Enter the function name: ")
        self.import_functions(file_path)
        if function_name in self.functions:
            for line in self.functions[function_name]:
                self.interpret(line)
        else:
            print(f"Function '{function_name}' is not defined in '{file_path}'.")

    def debug_interpreter(self, interpreter, file_path, running_from_file, arguments):
        current_line = 0
        breakpoints = set()
        log_file = None
        self.variables["argv"] = arguments
        self.variables["file"] = os.path.abspath(file_path)

        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        try:
            with open(file_path, 'r') as file:
                program = file.read()
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
            return

        program = program.replace('\n', ";")
        rep_in_func = False
        char_ = 0
        prog = list(program)
        for char in prog:
            if char == "{":
                rep_in_func += 1
            elif char == "}":
                rep_in_func -= 1
            elif rep_in_func != 0  and char == ";":
                prog[char_] = "|"
            char_ += 1
        prog2 = ""
        for char in prog:
            prog2+=char
        program = prog2

        if not self.in_func:
            self.current_line = 0

        lines = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', program)
        lines = [stmt.strip() for stmt in lines if stmt.strip()]

        commands_info = {
            's': 'Step to the next line',
            'c': 'Continue to the next breakpoint',
            'b <line>': 'Add a breakpoint at the specified line number',
            'r <line>': 'Remove a breakpoint at the specified line number',
            'l': 'List all current breakpoints',
            'v': 'View all variables',
            'f': 'View all functions',
            'log': 'Set the log file name (default is log.txt)',
            'exit': 'Exit the debugger',
            'help': 'Show this help message'
        }

        def print_help():
            print("Available commands:")
            for cmd, desc in commands_info.items():
                print(f"{cmd}: {desc}")

        def log_message(message):
            if log_file:
                with open(log_file, 'a') as f:
                    f.write(message + '\n')

        print("Debugger started. Type 'help' for a list of commands.")
        log_message("Debugger started.")

        while True:
            command = input("Debugger> ").strip()

            if command == 's':
                log_message("User chose to step.")
                break
            elif command == 'c':
                log_message("User chose to continue to the next breakpoint.")
                break
            elif command.startswith('b '):
                try:
                    line_num = int(command.split()[1])
                    breakpoints.add(line_num-1)
                    print(f"Breakpoint added at line {line_num}.")
                    log_message(f"Breakpoint added at line {line_num}.")
                except ValueError:
                    print("Invalid line number. Usage: b <line_number>")
            elif command.startswith('r '):
                try:
                    line_num = int(command.split()[1])
                    breakpoints.discard(line_num)
                    print(f"Breakpoint removed at line {line_num}.")
                    log_message(f"Breakpoint removed at line {line_num}.")
                except ValueError:
                    print("Invalid line number. Usage: r <line_number>")
            elif command == 'l':
                print("Breakpoints:", sorted(breakpoints))
                log_message(f"Breakpoints listed: {sorted(breakpoints)}")
            elif command == 'v':
                print("Variables:", interpreter.variables)
                log_message(f"Variables: {interpreter.variables}")
            elif command == 'f':
                print("Functions:", interpreter.functions)
                log_message(f"Functions: {interpreter.functions}")
            elif command == 'log':
                log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                print(f"Logging to {log_file}")
                log_message(f"Log file set to: {log_file}")
            elif command == 'exit':
                print("Exiting debugger.")
                log_message("Debugger exited.")
                return
            elif command == 'help':
                print_help()
            elif command == 'clear':
                if os.name == "posix":
                    os.system('clear')
                else:
                    os.system('cls')
            else:
                print("Unknown command. Type 'help' for a list of commands.")

        while current_line < len(lines):
            line = lines[current_line].strip()

            if current_line in breakpoints:
                print(f"Breakpoint hit at line {current_line + 1}.")
                log_message(f"Breakpoint hit at line {current_line + 1}.")
            
            if not line.startswith("#") and line != "":
                print(f"Debug: Executing line {current_line + 1}: {line}")
                log_message(f"Executing line {current_line + 1}: {line}")

                try:
                    interpreter.interpret(line)
                except Exception as e:
                    error_message = f"Error executing line {current_line + 1}: {e}"
                    print(error_message)
                    log_message(error_message)
            current_line += 1

            while True:
                command = input("Debugger> ").strip()

                if command == 's':
                    log_message("User chose to step.")
                    break
                elif command == 'c':
                    log_message("User chose to continue to the next breakpoint.")
                    while current_line < len(lines) and current_line not in breakpoints:
                        line = lines[current_line].strip()
                        if not line.startswith("#") and line != "":
                            print(f"Debug: Executing line {current_line + 1}: {line}")
                            log_message(f"Executing line {current_line + 1}: {line}")

                            try:
                                interpreter.interpret(line)
                            except Exception as e:
                                error_message = f"Error executing line {current_line + 1}: {e}"
                                print(error_message)
                                log_message(error_message)
                        current_line += 1
                    break
                elif command.startswith('b '):
                    try:
                        line_num = int(command.split()[1])
                        breakpoints.add(line_num)
                        print(f"Breakpoint added at line {line_num}.")
                        log_message(f"Breakpoint added at line {line_num}.")
                    except ValueError:
                        print("Invalid line number. Usage: b <line_number>")
                elif command.startswith('r '):
                    try:
                        line_num = int(command.split()[1])
                        breakpoints.discard(line_num)
                        print(f"Breakpoint removed at line {line_num}.")
                        log_message(f"Breakpoint removed at line {line_num}.")
                    except ValueError:
                        print("Invalid line number. Usage: r <line_number>")
                elif command == 'l':
                    print("Breakpoints:", sorted(breakpoints))
                    log_message(f"Breakpoints listed: {sorted(breakpoints)}")
                elif command == 'v':
                    print("Variables:", interpreter.variables)
                    log_message(f"Variables: {interpreter.variables}")
                elif command == 'f':
                    print("Functions:", interpreter.functions)
                    log_message(f"Functions: {interpreter.functions}")
                elif command == 'log':
                    log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                    print(f"Logging to {log_file}")
                    log_message(f"Log file set to: {log_file}")
                elif command == 'exit':
                    print("Exiting debugger.")
                    log_message("Debugger exited.")
                    return
                elif command == 'help':
                    print_help()
                elif command == 'clear':
                    if os.name == "posix":
                        os.system('clear')
                    else:
                        os.system('cls')
                else:
                    print("Unknown command. Type 'help' for a list of commands.")
        if running_from_file == True:
            cvf = input("Clear variables and functions dictionaries? (y/n): ")
            if cvf.lower() == "y":
                interpreter.variables.clear()
                interpreter.functions.clear()


    def parse_call_statement(self, statement):
        if statement.startswith("(") and statement.endswith(")"):
            statement = statement[1:-1]
            parts = [part.strip() for part in statement.split(",")]
            
            if len(parts) < 2:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variabes["err"] = 46
                    print("Invalid number of arguments for call")
                else:
                    self.variables["err"] = 46
            
            file_name = parts[0]
            function_name = parts[1]
            
            args = parts[2:]
            
            if file_name.startswith('"') and file_name.endswith('"'):
                file_name = file_name[1:-1]
            else:
                file_name = self.variables[file_name]
            if function_name.startswith('"') and function_name.endswith('"'):
                function_name = function_name[1:-1]
            else:
                function_name = self.variables[function_name]
            for arg in args:
                if arg.startswith('"') and arg.endswith('"') and len(arg) > 2:
                    arg = arg[1:-1]
                else:
                    arg = self.variables[arg]
            
            return file_name, function_name, args
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 47
                print("Invalid call statement format. Expected format: call(file_name, function_name, arg1, arg2, ...)")
            else:
                self.variables["err"] = 47

    def call_function_from_file(self, file_name, function_name, args):
        if not os.path.isfile(file_name):
            print(f"File '{file_name}' does not exist.")
            return

        spec = importlib.util.spec_from_file_location("module.name", file_name)
        
        if spec is None:
            print(f"Could not load the module from '{file_name}'.")
            return
        
        module = importlib.util.module_from_spec(spec)
        
        try:
            spec.loader.exec_module(module)
        except Exception as e:
            print(f"Error loading module '{file_name}': {e}")
            return

        if hasattr(module, function_name):
            func = getattr(module, function_name)
            if callable(func):
                converted_args = []
                for arg in args:
                    if arg.startswith('"') and arg.endswith('"'):
                        converted_args.append(arg[1:-1])
                    elif arg.isdigit():
                        converted_args.append(int(arg))
                    elif arg in self.variables:
                        converted_args.append(self.variables[arg])
                    else:
                        converted_args.append(arg)
                func(self, *converted_args)
            else:
                print(f"'{function_name}' is not callable in '{file_name}'.")
        else:
            print(f"Function '{function_name}' is not defined in '{file_name}'.")


    def print_help(self):
        print("""
commands:
    file - run a program from a file
    cls - clear the functions and variables dictionaries
    clear - clear the console
    debug - start debugging mode
    func - execute a function from a file
    history - show the commands history
    history <number> - execute the command from the history by number
    history clear - clear the commands history
    history <term> - search the commands history for a term
    info - show the interpreter version along with some other information
    ppm - lunch the Pryzma Package Manager shell
    ppm <command> - execute a Pryzma package manager command
    errors - show the error codes table
    exit - exit the interpreter
    reboot - reboot the interpreter
    help - show this help
    license - show the license
""")


    def display_system_info():
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        os_info = platform.system() + " " + platform.release()
        
        cpu_info = platform.processor()
        
        machine_arch = platform.machine()
        if machine_arch in ['x86_64', 'AMD64']:
            arch_info = '64-bit'
        elif machine_arch in ['i386', 'i686']:
            arch_info = '32-bit'
        else:
            arch_info = 'Unknown'

        print(f"Pryzma {version}")
        print(f"Current Date and Time: {current_time}")
        print(f"Operating System: {os_info} {arch_info} ({machine_arch})")
        print(f"Processor: {cpu_info}")

        
    def print_error_codes_table():
        print(
"""
1 - Error keyword deleted 
2 - Invalid function definition 
3 - Function not defined
4 - Too much arguments for +=
5 - Too much arguments for -=
6 - Invalid number of arguments for write()
7 - Invalid move() instruction syntax
8 - Invalid index for move() instruction
9 - Invalid swap() instruction syntax
10 - Invalid index for swap() instruction
11 - Invalid create_button command
12 - Invalid create_label command
13 - Invalid create_entry command
14 - Invalid get_entry_text command
15 - Invalid set_entry_text command
16 - Tkintet isn't enabled
17 - Invalid statement
18 - Unknown error
19 - Module does not have a 'start' function."
20 - Error loading module
21 - Cannot decrement non-integer variable
22 - Variable not found for decrement function
23 - Cannot increment non-integer variable
24 - Variable not found for increment function
25 - Error writing to file
26 - Invalid number of arguments for replace function
27 - Invalid number of arguments for resplit function
28 - The first argument of resplit() must be a string (regex pattern).
29 - The second argument of resplit() must be a string.
30 - Invalid regex pattern.
31 - in() function error
32 - Invalid number of arguments for splitby function
33 - File not found
34 - Invalid number of arguments for index function 
35 - Value not found in list for index function
36 - Variable is not a list for index function
37 - List not defined for all()
38 - Variable is not defined for isanumber()
39 - Invalid argument for dirname()
40 - Unknown variable or expression
41 - Invalid range expression for loop
42 - File not found for use function
43 - List does not exist for append function
44 - Index out of range for pop function
45 - List does not exist for pop function
46 - Invalid number of arguments for call.
47 - Invalid call statement format.
""" 
)


class X86Emulator:
    def __init__(self):
        from keystone import Ks, KS_ARCH_X86, KS_MODE_64
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
        from unicorn.x86_const import (
            UC_X86_REG_RAX,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RSI,
            UC_X86_REG_RDI,
            UC_X86_REG_RSP,
        )

        self.Ks = Ks
        self.KS_ARCH_X86 = KS_ARCH_X86
        self.KS_MODE_64 = KS_MODE_64
        self.Uc = Uc
        self.UC_ARCH_X86 = UC_ARCH_X86
        self.UC_MODE_64 = UC_MODE_64
        self.UcError = UcError

        self.UC_X86_REG_RAX = UC_X86_REG_RAX
        self.UC_X86_REG_RBX = UC_X86_REG_RBX
        self.UC_X86_REG_RCX = UC_X86_REG_RCX
        self.UC_X86_REG_RDX = UC_X86_REG_RDX
        self.UC_X86_REG_RSI = UC_X86_REG_RSI
        self.UC_X86_REG_RDI = UC_X86_REG_RDI
        self.UC_X86_REG_RSP = UC_X86_REG_RSP

        self.BASE_ADDR = 0x1000000
        self.MEM_SIZE = 2 * 1024 * 1024
        self.STACK_ADDR = self.BASE_ADDR + self.MEM_SIZE - 0x1000

        self.register_order = [
            self.UC_X86_REG_RAX,
            self.UC_X86_REG_RBX,
            self.UC_X86_REG_RCX,
            self.UC_X86_REG_RDX,
            self.UC_X86_REG_RSI,
            self.UC_X86_REG_RDI
        ]

    def _get_reg_name(self, uc_reg):
        return {
            self.UC_X86_REG_RAX: 'rax',
            self.UC_X86_REG_RBX: 'rbx',
            self.UC_X86_REG_RCX: 'rcx',
            self.UC_X86_REG_RDX: 'rdx',
            self.UC_X86_REG_RSI: 'rsi',
            self.UC_X86_REG_RDI: 'rdi',
        }.get(uc_reg, 'unknown')

    def _parse_script(self, script: str, variables: dict):
        asm_match = re.search(r'asm\s*{(.*?)}', script, re.DOTALL)
        return asm_match.group(1).strip() if asm_match else ""

    def _resolve_variables(self, asm: str, variables: dict):
        reg_map = {}
        mem_map = {}
        resolved_asm = asm
        mem_cursor = 0x1000

        for i, (var, val) in enumerate(variables.items()):
            if i < len(self.register_order):
                reg = self.register_order[i]
                reg_map[var] = (reg, val)
                resolved_asm = re.sub(rf'\b{var}\b', self._get_reg_name(reg), resolved_asm)
            else:
                addr = self.BASE_ADDR + mem_cursor
                mem_map[var] = (addr, val)
                resolved_asm = re.sub(rf'\b{var}\b', f"[{hex(addr)}]", resolved_asm)
                mem_cursor += 8

        return resolved_asm, reg_map, mem_map

    def _assemble(self, asm: str) -> bytes:
        ks = self.Ks(self.KS_ARCH_X86, self.KS_MODE_64)
        encoding, _ = ks.asm(asm)
        return bytes(encoding)

    def _emulate(self, code: bytes, reg_map: dict, mem_map: dict):
        mu = self.Uc(self.UC_ARCH_X86, self.UC_MODE_64)
        mu.mem_map(self.BASE_ADDR, self.MEM_SIZE)
        mu.mem_write(self.BASE_ADDR, code)
        mu.reg_write(self.UC_X86_REG_RSP, self.STACK_ADDR)

        for reg, val in reg_map.values():
            mu.reg_write(reg, val)

        for addr, val in mem_map.values():
            mu.mem_write(addr, val.to_bytes(8, 'little'))

        try:
            mu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(code))
        except Exception as e:
            print("Emulation error:", e)

        results = {}
        for name, (reg, _) in reg_map.items():
            val = mu.reg_read(reg)
            results[name] = val

        for name, (addr, _) in mem_map.items():
            val = int.from_bytes(mu.mem_read(addr, 8), 'little')
            results[name] = val

        return results

    def run(self, script: str, variables: dict):
        asm = self._parse_script(script, variables)
        resolved_asm, reg_map, mem_map = self._resolve_variables(asm, variables)
        code = self._assemble(resolved_asm)
        return self._emulate(code, reg_map, mem_map)


class PackageManager:
    user_packages_path = os.path.dirname(os.path.abspath(__file__)) + "/packages/"
    package_api_url = "http://igorcielniak.pythonanywhere.com/api/download"

    def remove_package(self, package_name):
        package_dir = os.path.join(self.user_packages_path, package_name)
        if os.path.exists(package_dir):
            shutil.rmtree(package_dir)
            print("Package", package_name, "removed successfully.")
        else:
            print("Package", package_name, "not found.")

    def list_packages(self):
        packages = os.listdir(self.user_packages_path)
        if packages:
            print("Available packages:")
            for package in packages:
                print("-", package)
        else:
            print("No packages installed.")


    def install_package(self, package_name):
        package_url = f"{self.package_api_url}/{package_name}"
        import_err = False
        try:
            import requests
        except ImportError:
            import_err = True
            print("module requests not found")
        if not import_err:
            try:
                response = requests.get(package_url)
                if response.status_code == 200:
                    package_dir = os.path.join(self.user_packages_path, package_name)
                    os.makedirs(package_dir, exist_ok=True)
    
                    package_file_path = os.path.join(package_dir, f"{package_name}.zip")
                    with open(package_file_path, 'wb') as file:
                        file.write(response.content)

                    with zipfile.ZipFile(package_file_path, 'r') as zip_ref:
                        zip_ref.extractall(package_dir)
    
                    os.remove(package_file_path)
                    print("Package", package_name, "downloaded and installed successfully.")
                else:
                    print("Package", package_name, "not found in the repository.")
            except requests.exceptions.ConnectionError as ex:
                print("Connection error, check your inernet connection.")


    def update_package(self, package_name=None):
        if package_name:
            self.install_package(PackageManager,package_name)
        else:
            packages = os.listdir(self.user_packages_path)
            for package in packages:
                self.install_package(PackageManager,package)

    def get_package_info(self, package_name):
        package_dir = os.path.join(self.user_packages_path, package_name)
        metadata_path = os.path.join(package_dir, "metadata.json")
        
        if os.path.exists(metadata_path):
            with open(metadata_path, "r") as metadata_file:
                metadata = json.load(metadata_file)
                print(package_name, metadata.get("version", "Version not specified."))
                print("Author:", metadata.get("author", "Author not specified."))
                print("Description:", metadata.get("description", "Description not specified."))
                print("License:", metadata.get("license", "License not specified."))
                print()
        else:
            print("Package metadata not found.")

    def display_help(self):
        help_text = """
Available commands:
    - remove <package_name>: Remove a package from the repository.
    - list: List all installed packages.
    - install <package_name>: Install a package from the repository.
    - update <package_name>: Update a specific package or all packages if no name is provided.
    - show <package_name>: Show information about a specific package or all packages if no name is provided.
    - help: Show this help message.
    - exit: Exit the Pryzma package manager.
        """
        print(help_text)
    
    def execute_ppm_command(self,user_input):
        if user_input[0] == "help":
            self.display_help(PackageManager)
        elif user_input[0] == "remove":
            if len(user_input) > 1:
                self.remove_package(PackageManager, user_input[1])
            else:
                print("Please provide a package name.")
        elif user_input[0] == "list":
            self.list_packages(PackageManager)
        elif user_input[0] == "install":
            if len(user_input) > 1:
                self.install_package(PackageManager, user_input[1])
            else:
                print("Please provide a package name.")
        elif user_input[0] == "update":
            if len(user_input) > 1:
                self.update_package(PackageManager, user_input[1])
            else:
                self.update_package(PackageManager)
        elif user_input[0] == "show":
            if len(user_input) > 1:
                self.get_package_info(PackageManager, user_input[1])
            else:
                if os.listdir(self.user_packages_path):
                    for package_name in os.listdir(self.user_packages_path):
                        self.get_package_info(PackageManager, package_name)
                else:
                    print("No packages installed.")
        elif user_input[0] == "clear":
            os.system('cls' if os.name == 'nt' else 'clear')
        else:
            print("Unknown command. Type 'help' for available commands.")

    def shell_mode(self):
        print("ppm shell. Type 'exit' to quit.")
        while True:
            user_input = input("> ").split()
            if user_input[0] == "exit":
                break
            else:
                self.execute_ppm_command(PackageManager, user_input)









def shell(code):
    history.append(code)
    if code == "help":
        interpreter.print_help()
    elif code == "cls":
        interpreter.variables.clear()
        interpreter.functions.clear()
    elif code == "clear":
        if os.name == "posix":
            os.system('clear')
        else:
            os.system('cls')
    elif code == "file":
        running_from_file = True
        interpreter.interpret_file2()
        cvf = input("Clear variables and functions dictionaries? (y/n): ")
        if cvf.lower() == "y":
            interpreter.variables.clear()
            interpreter.functions.clear()
        running_from_file = False
    elif code == "license":
        interpreter.show_license()
    elif code == "debug":
        running_from_file = True
        file_path = input("Path to the file to debug ('exit' to quit debug mode): ")
        if file_path != "exit":
            interpreter.debug_interpreter(interpreter, file_path, running_from_file, [])
        running_from_file = False
    elif code == "func":
        interpreter.execute_function_from_file()
    elif code.startswith("history"):
        code_parts = code.split()
        if len(code_parts) == 1:
            for index, command in enumerate(history, start=1):
                print(f"{index}. {command}")
        elif len(code_parts) == 2 and code_parts[1].isnumeric():
            command_index = int(code_parts[1]) - 1
            if 0 <= command_index < len(history):
                shell(history[command_index])
            else:
                print("Invalid history index.")
        elif len(code_parts) == 2 and code_parts[1] == "clear":
            history.clear()
        elif len(code_parts) == 2:
            search_term = code_parts[1]
            print(f"Searching for '{search_term}' in history:")
            found_commands = [cmd for cmd in history if search_term in cmd]
            if found_commands:
                for index, command in enumerate(found_commands, start=1):
                    print(f"{index}. {command}")
            else:
                print("No commands found matching the search term.")
        else:
                print("Invalid command. Usage: history [search_term | index | clear]")
    elif code.startswith("ppm"):
        if code == "ppm":
            if not os.path.exists(PackageManager.user_packages_path):
                os.makedirs(PackageManager.user_packages_path)
            PackageManager.shell_mode(PackageManager)
        else:
            if not os.path.exists(PackageManager.user_packages_path):
                os.makedirs(PackageManager.user_packages_path)
            code = code[len("ppm"):].strip()
            PackageManager.execute_ppm_command(PackageManager, code.split())
    elif code == "info":
        PryzmaInterpreter.display_system_info()
    elif code == "errors":
        PryzmaInterpreter.print_error_codes_table()
    else:
        interpreter.interpret(code)
        print("variables:", interpreter.variables, "\n")
        print("functions:", interpreter.functions, "\n")




def main():
    global interpreter
    global history
    global running_from_file
    global debug
    global tkinter_enabled
    global version

    interpreter = PryzmaInterpreter()

    tkinter_enabled = False
    history = []
    running_from_file = False
    version = 5.8

    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        arguments = sys.argv[1:]
        debug = False
        interpreter.preprocess_only = False
        interpret_line = False
        for arg in arguments:
            if interpret_line == True:
                interpreter.interpret(arg)
                sys.exit()
            if arg.startswith("-"):
                if arg == "-h":
                    print("""
flags:
    -d  - debug mode
    -p  - preprocces only
    -np - no preprocessing
    -l '<pryzma code>' - execute a single line
    -fd - forward declare all functions
                    """)
                    sys.exit()
                if arg == "-d":
                    arguments.remove(arg)
                    debug = True
                    interpreter.debug_interpreter(interpreter, file_path, running_from_file, arguments)
                if arg == "-p":
                    interpreter.preprocess_only = True
                if arg == "-np":
                    interpreter.no_preproc = True
                if arg == "-l":
                    interpret_line = True
                if arg == "-fd":
                    interpreter.forward_declare = True
        if debug == False:
            interpreter.interpret_file(file_path, *arguments)
        sys.exit()

    print(f"""Pryzma {version}
To show the license type "license" or "help" to get help.
    """)

    while True:
        code = input("/// ")
        if code == "exit":
            break
        elif code == "reboot":
            os.execl(sys.executable, sys.executable, *sys.argv)
        shell(code)



if __name__ == "__main__":
    main()
