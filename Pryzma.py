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
import ctypes
from collections import UserDict
import lzma

class Reference:
    def __init__(self, var_name):
        self.var_name = var_name

class FuncReference:
    def __init__(self, func_name):
        self.func_name = func_name

class eval_dict(UserDict):
    def __getitem__(self, key):
        value = super().__getitem__(key)
        return value() if callable(value) else value

class PryzmaInterpreter:
    
    def __init__(self):
        self.variables = eval_dict({})
        self.functions = {}
        self.structs = {}
        self.locals = {}
        self.tk_vars = {}
        self.custom_handlers = {}
        self.deleted_keywords = []
        self.variables["interpreter_path"] = __file__
        self.variables["err"] = 0
        self.in_try_block = False
        self.in_func = [False]
        self.function_tracker = [None]
        self.current_func_name = None
        self.preprocess_only = False
        self.no_preproc = False
        self.forward_declare = False
        self.nan = False
        self.return_val = None
        self.break_stack = []
        self.main_file = 1
        self.mem = bytearray(4096)
        self.fail = False
        self.unpack_ = False

    def interpret_file(self, file_path, *args):
        self.file_path = file_path.strip('"')
        self.variables["argv"] = args
        self.variables["__file__"] = os.path.abspath(file_path)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            if data.startswith("prz".encode('utf-8')):
                data = data[3:]
                self.unpack_ = True

            if self.unpack_ == True:
                self.interpret(self.unpack(file_path))
            else:
                with open(self.file_path, 'r') as file:
                    program = file.read()
                    self.interpret(program)
        except FileNotFoundError:
            print(f"File '{self.file_path}' not found.")

    def preprocess(self, program):
        program = program.splitlines()
        for line in range(0,len(program)-1):
            program[line] = program[line].split("//")[0]
            if program[line].startswith("#np") or (program[line].startswith("#preproc") and "np" in program[line]):
                self.no_preproc = True
        program = ";".join(program)


        if not self.no_preproc:
            rep_in_func = 0
            char_ = 0
            prog = list(program)
            in_str = False
            for char in prog:
                if char == "{" and not in_str:
                    rep_in_func += 1
                elif char == "}" and not in_str:
                    rep_in_func -= 1
                elif char == '"':
                    in_str = not in_str
                elif rep_in_func != 0  and char == ";" and not in_str:
                    prog[char_] = "|"
                char_ += 1
            prog2 = ""
            for char in prog:
                prog2+=char
            program = prog2

        lines = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', program)
        return [stmt.strip() for stmt in lines if stmt.strip()]


    def interpret(self, program):
        if self.main_file < 1:
            self.no_preproc = False

        self.main_file -= 1

        if not self.in_func[-1]:
            self.current_line = 0

        lines = self.preprocess(program)

        if self.preprocess_only == True:
            for line in lines:
                print(line)
            try:
                return lines
            except:
                pass
            finally:
                sys.exit()

        if self.forward_declare == True:
            self.forward_declare = False
            for i, line in enumerate(lines):
                self.current_line = i
                if line.startswith("/"):
                    self.interpret(line)
                    lines[i] = ""
            self.current_line = 0


        for line in lines:
            self.current_line += 1
            line = line.strip()

            if line == "" or line.startswith("//"):
                continue
            if "//" in line:
                line = line.split("//")[0]

            deleted_keyword = False

            for key_word in self.deleted_keywords:
                if key_word in line and not (line.startswith("disablekeyword(") or line.startswith("enablekeyword(")):
                    keyword = key_word
                    deleted_keyword = True

            if deleted_keyword:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 1
                    print(f"Error near line {self.current_line}: keyword deleted '{keyword}'")
                    if self.fail:
                        sys.exit()
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
                elif line.startswith("#"):
                    if line.startswith("#preproc"):
                        if "=" in line:
                            self.process_args(line.split("=")[1].split(","))
                    elif line.startswith("#replace"):
                        a, b = line[8:].split("->")
                        a = str(self.evaluate_expression(a.strip()))
                        b = str(self.evaluate_expression(b.strip()))
                        for i, line in enumerate(lines):
                            lines[i] = re.sub(a, b, line)
                    elif line.startswith("#insert"):
                        file = self.evaluate_expression(line[7:].strip())
                        with open(file) as f:
                            self.interpret(f.read())
                    elif line == "#shell":
                        while True:
                            code = input("/// ")
                            if code == "exit":
                                break
                            shell(code)
                    else:
                        self.process_args(line[1:].split(","))
                elif line.startswith("struct"):
                    line = line[6:]
                    name, fields = line[:-1].split("{", 1)
                    name = name.strip()
                    fields = self.struct_split(fields.strip())
                    for i, field in enumerate(fields):
                        fields[i] = field.strip()
                    fields = list(filter(None, fields))
                    fields_dict = {}
                    for field in fields:
                        if not field:
                            continue
                        if "=" not in field:
                            fields_dict[field] = None
                        else:
                            key, value = field.split("=", 1)
                            fields_dict[key.strip()] = self.evaluate_expression(value.strip()) if not repr(value.strip()).startswith("@") else value.strip()
                    self.structs[name] = fields_dict
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
                            for_body[char_] = "#@!$^%"
                        char_ += 1

                    for_body2 = ""
                    for char in for_body:
                        for_body2 += char
                    actions = for_body2.split("#@!$^%")
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
                            if self.fail:
                                sys.exit()
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
                            for_body[char_] = "*!@#$%&"
                        char_ += 1

                    for_body2 = ""
                    for char in for_body:
                        for_body2 += char
                    actions = for_body2.split("*!@#$%&")
                    loop_var, range_expr = range_expr.split(",")
                    loop_var = loop_var.strip()
                    range_expr = range_expr.strip()
                    for action in actions:
                        action = action.strip()
                    self.for_loop(loop_var, range_expr, actions)
                elif line.startswith("use"):
                    if "with" in line:
                        line, directive = line.split("with")
                        if directive.strip() != "":
                            nan = self.nan
                            fd = self.forward_declare
                            np = self.no_preproc
                            self.process_args(directive.strip()[1:].split(","))
                            file_path = line[3:].strip()
                            self.import_functions(file_path)
                            self.nan = nan
                            self.forward_declare = fd
                            self.no_preproc = np
                    else:
                        file_path = line[3:].strip()
                        self.import_functions(file_path)
                elif line.startswith("from"):
                    if "with" in line:
                        line, directive = line.split("with")
                        line = line.strip()
                        module, functions = line[4:].strip().split("use")
                        module = module.strip()
                        if '/' in module or '\\' in module:
                            pass
                        else:
                            if "::" in module:
                                args = module.split("::")
                                file = args.pop()
                                folder = "/".join(args)
                                module = f"{PackageManager.user_packages_path}/{folder}/{file}.pryzma"
                            else:
                                module = f"{PackageManager.user_packages_path}/{module}/{module}.pryzma"
                        functions = functions.strip().split(",")
                        if directive.strip() != "":
                            nan = self.nan
                            fd = self.forward_declare
                            np = self.no_preproc
                            self.process_args(directive.strip()[1:].split(","))
                            for function in functions:
                                self.load_function_from_file(module, function.strip())
                            self.nan = nan
                            self.forward_declare = fd
                            self.no_preproc = np
                    else:
                        module, functions = line[4:].strip().split("use")
                        module = module.strip()
                        if '/' in module or '\\' in module:
                            pass
                        else:
                            if "::" in module:
                                args = module.split("::")
                                file = args.pop()
                                folder = "/".join(args)
                                module = f"{PackageManager.user_packages_path}/{folder}/{file}.pryzma"
                            else:
                                module = f"{PackageManager.user_packages_path}/{module}/{module}.pryzma"
                        functions = functions.strip().split(",")
                        for function in functions:
                            self.load_function_from_file(module, function.strip())
                elif line.startswith("if"):
                    else_ = False
                    if "else" in line:
                        line = list(line)
                        else_ = True
                        depth = 0
                        in_str = False
                        for i, char in enumerate(line):
                            if char == "{" and not in_str:
                                depth += 1
                            elif char == "}" and not in_str:
                                depth -= 1
                            elif char == '"':
                                in_str = not in_str
                            elif depth == 0 and char == "e" and line[i + 1] == "l" and line[i + 2] == "s" and line[i + 3] == "e":
                                line[i] = "#"
                                line[i + 1] = "$"
                                line[i + 2] = "%"
                                line[i + 3] = "@"
                        sline = "".join(line).split("#$%@")
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
                            if_body[char_] = "#!%&*"
                        char_ += 1
                    if_body2 = ""
                    for char in if_body:
                        if_body2 += char
                    actions = if_body2.split("#!%&*")
                    if "==" in condition:
                        value1 = self.evaluate_expression(condition.split("==")[0].strip())
                        value2 = self.evaluate_expression(condition.split("==")[1].strip())
                        if value1 == value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif "!=" in condition:
                        value1 = self.evaluate_expression(condition.split("!=")[0].strip())
                        value2 = self.evaluate_expression(condition.split("!=")[1].strip())
                        if value1 != value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif "<=" in condition:
                        value1 = self.evaluate_expression(condition.split("<=")[0].strip())
                        value2 = self.evaluate_expression(condition.split("<=")[1].strip())
                        if value1 <= value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif ">=" in condition:
                        value1 = self.evaluate_expression(condition.split(">=")[0].strip())
                        value2 = self.evaluate_expression(condition.split(">=")[1].strip())
                        if value1 >= value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif "<" in condition:
                        value1 = self.evaluate_expression(condition.split("<")[0].strip())
                        value2 = self.evaluate_expression(condition.split("<")[1].strip())
                        if value1 < value2:
                            handeled = True
                            for action in actions:
                                self.interpret(action)
                    elif ">" in condition:
                        value1 = self.evaluate_expression(condition.split(">")[0].strip())
                        value2 = self.evaluate_expression(condition.split(">")[1].strip())
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
                                body[char_] = "$@#%^&"
                            char_ += 1
                        body2 = ""
                        for char in body:
                            body2 += char
                        actions = body2.split("$@#%^&")
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
                            if_body[char_] = "%$#@!"
                        char_ += 1
                    if_body2 = ""
                    for char in if_body:
                        if_body2 += char
                    actions = if_body2.split("%$#@!")
                    if "==" in condition:
                        value1 = self.evaluate_expression(condition.split("==")[0].strip())
                        value2 = self.evaluate_expression(condition.split("==")[1].strip())
                        self.break_stack.append(False)
                        while value1 == value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("==")[0].strip())
                                value2 = self.evaluate_expression(condition.split("==")[1].strip())
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif "!=" in condition:
                        value1 = self.evaluate_expression(condition.split("!=")[0].strip())
                        value2 = self.evaluate_expression(condition.split("!=")[1].strip())
                        self.break_stack.append(False)
                        while value1 != value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("!=")[0].strip())
                                value2 = self.evaluate_expression(condition.split("!=")[1].strip())
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif "<=" in condition:
                        value1 = self.evaluate_expression(condition.split("<=")[0].strip())
                        value2 = self.evaluate_expression(condition.split("<=")[1].strip())
                        self.break_stack.append(False)
                        while value1 <= value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("<=")[0].strip())
                                value2 = self.evaluate_expression(condition.split("<=")[1].strip())
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif ">=" in condition:
                        value1 = self.evaluate_expression(condition.split(">=")[0].strip())
                        value2 = self.evaluate_expression(condition.split(">=")[1].strip())
                        self.break_stack.append(False)
                        while value1 >= value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split(">=")[0].strip())
                                value2 = self.evaluate_expression(condition.split(">=")[1].strip())
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif "<" in condition:
                        value1 = self.evaluate_expression(condition.split("<")[0].strip())
                        value2 = self.evaluate_expression(condition.split("<")[1].strip())
                        self.break_stack.append(False)
                        while value1 < value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split("<")[0].strip())
                                value2 = self.evaluate_expression(condition.split("<")[1].strip())
                                if self.break_stack[-1]:
                                    break
                            if self.break_stack[-1]:
                                break
                        self.break_stack.pop()
                    elif ">" in condition:
                        value1 = self.evaluate_expression(condition.split(">")[0].strip())
                        value2 = self.evaluate_expression(condition.split(">")[1].strip())
                        self.break_stack.append(False)
                        while value1 > value2:
                            for action in actions:
                                self.interpret(action)
                                value1 = self.evaluate_expression(condition.split(">")[0].strip())
                                value2 = self.evaluate_expression(condition.split(">")[1].strip())
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
                        in_str = False
                        for char in function_body:
                            if char == "{" and not in_str:
                                rep_in_func += 1
                            elif char == "}" and not in_str:
                                rep_in_func -= 1
                            elif char == '"':
                                in_str = not in_str
                            elif rep_in_func == 0  and char == "|" and not in_str:
                                function_body[char_] = "@#%^$"
                            char_ += 1
                        function_body2 = ""
                        for char in function_body:
                            function_body2 += char
                        function_body = list(filter(None, function_body2.split("@#%^$")))
                        self.functions[function_name] = function_body
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 2
                            print(f"Invalid function definition at line {self.current_line}")
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 2
                elif line.startswith("@"):
                    self.in_func.append(True)
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
                    self.function_tracker.append(function_name)
                    if function_name in self.variables and isinstance(self.variables[function_name], FuncReference):
                        function_name = self.variables[function_name].func_name
                    if function_name not in self.functions:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 48
                            print(f"Error near line {self.current_line}: Referenced function '{function_name}' no longer exists")
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 48
                        continue
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
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 3
                    self.in_func.pop()
                    self.function_tracker.pop()
                elif line.startswith("pyeval(") and line.endswith(")"):
                    parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[7:-1])
                    if len(parts) == 1:
                        return eval(self.evaluate_expression(parts[0]))
                    else:
                        return eval(self.evaluate_expression(parts[0]),self.evaluate_expression(parts[1]))
                elif line.startswith("pyexec(") and line.endswith(")"):
                    parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[7:-1])
                    if len(parts) == 1:
                        return exec(self.evaluate_expression(parts[0]))
                    else:
                        return exec(self.evaluate_expression(parts[0]),self.evaluate_expression(parts[1]))
                elif line.startswith("exec(") and line.endswith(")"):
                    code = line[5:-1]
                    if "|" in code:
                        code = code.split("|")
                        for part in code:
                            self.interpret(self.evaluate_expression(part))
                    else:
                        self.interpret(self.evaluate_expression(code))
                elif line.startswith("try{") and line.endswith("}"):
                    self.in_try_block = True
                    catch_block = None
                    if "catch(" in line:
                        line, catch_block = line.split("catch(", 1)
                    instructions = line[4:-1].split("|")
                    error = 0
                    for instruction in instructions:
                        self.interpret(instruction.strip())
                        if self.variables["err"] != 0:
                            error = self.variables["err"]
                    self.variables["err"] = error
                    if catch_block:
                        err_code, instructions = catch_block[:-1].split("){", 1)
                        if int(err_code) == error:
                            instructions = instructions.split("|")
                            for instruction in instructions:
                                self.interpret(instruction.strip())
                    self.in_try_block = False
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
                elif line.startswith("loc"):
                    var, value = line[3:].split("=", 1)
                    var = var.strip()
                    value = value.strip()
                    self.locals[var] = self.function_tracker[-1]
                    self.assign_value(var, value)
                elif line.startswith("assert"):
                    parts = line[6:].strip().split(",", 1)
                    condition = parts[0].strip()
                    message = parts[1].strip()

                    result = eval(condition, {}, self.variables)
                    if not result:
                        raise AssertionError(f"AssertionError: {self.evaluate_expression(message)}")
                elif "=" in line and not line.strip().startswith(("if", "while")) and not any(op in line for op in ["+=", "-=", "==", "!=", "<=", ">="]):
                    variables, expression = line.split('=', 1)
                    variables = variables.strip().split(",")
                    expression = expression.strip()
                    for variable in variables:
                        self.assign_value(variable.strip(), expression)
                elif "+=" in line:
                    line = line.split("+=")
                    if len(line) != 2:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 4
                            print(f"Error near line {self.current_line}: Too much arguments")
                            if self.fail:
                                sys.exit()
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
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 5
                        continue
                    var = line[0].strip()
                    var2 = line[1].strip()
                    var2 = self.evaluate_expression(var2)
                    self.variables[var] -= var2
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
                elif line.startswith("sys(") and line.endswith(")"):
                    os.system(self.evaluate_expression(line[4:-1].strip()))
                elif line.startswith("file_write(") and line.endswith(")"):
                    line = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[11:-1])
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
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 6
                elif line.startswith("delvar(") and line.endswith(")"):
                    self.variables.pop(self.evaluate_expression(line[7:-1]))
                elif line.startswith("delfunc(") and line.endswith(")"):
                    self.functions.pop(self.evaluate_expression(line[8:-1]))
                elif line.startswith("disablekeyword(") and line.endswith(")"):
                    args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[15:-1])
                    for arg in args:
                        self.deleted_keywords.append(self.evaluate_expression(arg))
                elif line.startswith("enablekeyword(") and line.endswith(")"):
                    args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[14:-1])
                    for arg in args:
                        self.deleted_keywords.remove(self.evaluate_expression(arg))
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
                            if self.fail:
                                sys.exit()
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
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 8
                elif line.startswith("swap(") and line.endswith(")"):
                    instructions = line[5:-1].split(",")
                    if len(instructions) != 3:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 9
                            print(f"Error near line {self.current_line}: Invalid swap instruction syntax. Expected format: swap(index 1, index 2, list name)")
                            if self.fail:
                                sys.exit()
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
                            print("Invalid index for swap()")
                            if self.fail:
                                sys.exit()
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
                            command = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', command)
                            window = command[0].strip()
                            title = self.evaluate_expression(command[1].strip())
                            self.tk_vars[window].title(title)
                        elif command.startswith("mainloop(") and command.endswith(")"):
                            command = command[9:-1]
                            self.tk_vars[command].mainloop()
                        elif command.startswith("create_button(") and command.endswith(")"):
                            command = command[14:-1]
                            command = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', command)
                            window = command[1].strip()
                            button_name = command[0].strip()
                            button_text = self.evaluate_expression(command[2].strip())
                            button_command = command[3].strip()
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
                                    if self.fail:
                                        sys.exit()
                                else:
                                    self.variables["err"] = 11
                            self.tk_vars[button_name].pack()
                        elif command.startswith("create_label(") and command.endswith(")"):
                            command = command[13:-1]
                            command = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', command)
                            window = command[1].strip()
                            label_name = command[0].strip()
                            label_text = self.evaluate_expression(command[2].strip())
                            if len(command) == 2:
                                self.tk_vars[label_name] = tk.Label(self.tk_vars[window])
                            elif len(command) == 3:
                                self.tk_vars[label_name] = tk.Label(self.tk_vars[window],text = label_text)
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 12
                                    print(f"Error near line {self.current_line}: Invalid create_label command")
                                    if self.fail:
                                        sys.exit()
                                else:
                                    self.variables["err"] = 12
                            self.tk_vars[label_name].pack()
                        elif command.startswith("create_entry(") and command.endswith(")"):
                            command = command[13:-1]
                            command = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', command)
                            window = command[1].strip()
                            entry_name = command[0].strip()
                            entry_text = self.evaluate_expression(command[2].strip())
                            if len(command) == 2:
                                self.tk_vars[entry_name] = tk.Entry(self.tk_vars[window])
                            elif len(command) == 3:
                                self.tk_vars[entry_name] = tk.Entry(self.tk_vars[window],text = entry_text)
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 13
                                    print(f"Error near line {self.current_line}: Invalid create_entry command")
                                    if self.fail:
                                        sys.exit()
                                else:
                                    self.variables["err"] = 13
                            self.tk_vars[entry_name].pack()
                        elif command.startswith("get_entry_text(") and command.endswith(")"):
                            command = command[15:-1]
                            command = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', command)
                            entry_name = command[0].strip()
                            variable_name = command[1].strip()
                            if entry_name in self.tk_vars:
                                self.variables[variable_name] = self.tk_vars[entry_name].get()
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 14
                                    print(f"Error near line {self.current_line}: Invalid get_entry_text command")
                                    if self.fail:
                                        sys.exit()
                                else:
                                    self.variables["err"] = 14
                        elif command.startswith("set_entry_text(") and command.endswith(")"):
                            command = command[15:-1]
                            command = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', command)
                            entry_name = command[0].strip()
                            variable_name = command[1].strip()
                            if entry_name in self.tk_vars:
                                self.tk_vars[entry_name].delete(0, tk.END)
                                self.tk_vars[entry_name].insert(0, self.variables[variable_name])
                            else:
                                if not self.in_try_block:
                                    self.in_func_err()
                                    self.variables["err"] = 15
                                    print(f"Error near line {self.current_line}: Invalid set_entry_text command")
                                    if self.fail:
                                        sys.exit()
                                else:
                                    self.variables["err"] = 15
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 16
                            print(f"Error near line {self.current_line}: tkinter isn't enabled")
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 16
                elif line.startswith("call"):
                    call_statement = line[4:].strip()
                    file_name, function_name, args = self.parse_call_statement(call_statement)
                    self.call_function_from_file(file_name, function_name, args)
                elif line.startswith("ccall"):
                    call_statement = line[5:].strip()
                    file_name, function_name, args = self.parse_call_statement(call_statement)
                    self.ccall_function_from_file(file_name, function_name, args)
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
                    self.ret_val = self.evaluate_expression(line[6:].strip())
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
                            processed_cases += "&@$%"
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
                            for instruction in case[1].split("&@$%"):
                                self.interpret(instruction)

                    if handeled == False and default_case:
                        for instruction in default_case[1].split("&@$%"):
                            self.interpret(instruction)
                elif line.startswith("write(") and line.endswith(")"):
                    addr, data = line[6:-1].split(",", 1)
                    addr = self.evaluate_expression(addr.strip())
                    data = self.evaluate_expression(data.strip())
                    self.mem[addr] = data
                elif line == "stop":
                    sys.exit()
                else:
                    if not handled:
                        if not self.in_try_block:
                            self.in_func_err()
                            self.variables["err"] = 17
                            print(f"Invalid statement at line {self.current_line}: {line}")
                            if self.fail:
                                sys.exit()
                        else:
                            self.variables["err"] = 17

            except Exception as e:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 18
                    print(f"Error near line {self.current_line}: {e}")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 18

    def in_func_err(self):
        if self.in_func[-1]:
            print(f"Error while calling function '{self.function_tracker[-1]}'")

    def compress(self, text: str) -> bytes:
        return lzma.compress(text.encode('utf-8'), preset=9 | lzma.PRESET_EXTREME)

    def decompress(self, data: bytes) -> str:
        try:
            return lzma.decompress(data).decode('utf-8')
        except Exception:
            print("Can't decompress data")
            sys.exit()

    def pack(self, file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            prog = f.read()
        prog = ";".join(self.preprocess(prog))
        prog = "#np;" + prog
        return bytes("prz".encode('utf-8')) + self.compress(prog)

    def unpack(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
        if data.startswith("prz".encode('utf-8')):
            data = data[3:]
        return self.decompress(data)

    def process_args(self, args):
        for arg in range(0,len(args)):
            args[arg] = args[arg].strip()
        if "fd" in args:
            self.forward_declare = True
        if "np" in args:
            self.no_preproc = True
        if "nan" in args:
            self.nan = True
        if "an" in args:
            self.nan = False
        if "fail" in args:
            self.fail = True
        if "df" in args:
            self.fail = False


    def struct_split(self, s):
        result = []
        current = []
        in_quotes = False
        brace_depth = 0
        i = 0
        while i < len(s):
            c = s[i]

            if c == '"':
                in_quotes = not in_quotes
                current.append(c)
            elif (c == '{' or c == '[') and not in_quotes:
                brace_depth += 1
                current.append(c)
            elif (c == '}' or c == ']') and not in_quotes:
                brace_depth -= 1
                current.append(c)
            elif (c == ',' or c == '|') and not in_quotes and brace_depth == 0:
                result.append(''.join(current).strip())
                current = []
            else:
                current.append(c)

            i += 1

        if current:
            result.append(''.join(current).strip())
        return result


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
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 19
        except Exception as e:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 20
                print(f"Error loading module '{module_path}': {e}")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 20

    def decrement_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int) or isinstance(self.variables[variable], float):
                self.variables[variable] -= 1
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 21
                    print(f"Error near line {self.current_line}: Cannot decrement non-integer or float variable '{variable}'.")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 21
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 22
                print(f"Error near line {self.current_line}: Variable '{variable}' not found.")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 22

    def increment_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int) or isinstance(self.variables[variable], float):
                self.variables[variable] += 1
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 23
                    print(f"Error near line {self.current_line}: Cannot increment non-integer or float variable '{variable}'.")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 23
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 24
                print(f"Error near line {self.current_line}: Variable '{variable}' not found.")
                if self.fail:
                    sys.exit()
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
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 25

    def add_or_index(self, expr):
        in_quotes = False
        escape = False
        bracket_depth = 0

        for char in expr:
            if char == '"' and not escape:
                in_quotes = not in_quotes
            elif char == '\\':
                escape = not escape
                continue
            elif not in_quotes:
                if char == '[':
                    bracket_depth += 1
                elif char == ']' and bracket_depth > 0:
                    bracket_depth -= 1
                elif char == '+' and bracket_depth > 0:
                    return True

            escape = False

        return False

    def add_or_str(self, expr):
        in_quotes = False
        escape = False
        has_unquoted_plus = False

        for char in expr:
            if char == '"' and not escape:
                in_quotes = not in_quotes
            elif char == '\\':
                escape = not escape
            elif char == '+' and not in_quotes:
                has_unquoted_plus = True
            else:
                escape = False

        return has_unquoted_plus

    def evaluate_expression(self, expression):
        if re.match(r"^\d+$", expression):
            return int(expression)
        elif expression.startswith("read(") and expression.endswith(")"):
            addr = self.evaluate_expression(expression[5:-1])
            return self.mem[addr]
        elif expression.startswith("/"):
            name = "_lambda" + str(random.getrandbits(32))
            self.interpret("/" + name +  expression[1:])
            return FuncReference(name)
        elif expression.startswith("pyeval(") and expression.endswith(")"):
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[7:-1])
            if len(parts) == 1:
                return eval(self.evaluate_expression(parts[0]))
            else:
                return eval(self.evaluate_expression(parts[0]),self.evaluate_expression(parts[1]))
        elif expression.startswith("pyexec(") and expression.endswith(")"):
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[7:-1])
            if len(parts) == 1:
                return exec(self.evaluate_expression(parts[0]))
            else:
                return exec(self.evaluate_expression(parts[0]),self.evaluate_expression(parts[1]))
        elif expression.startswith("eval(") and expression.endswith(")"):
            code = expression[5:-1]
            if "|" in code:
                code = code.split("|")
                for part in code:
                    self.ret_val = None
                    self.interpret(self.evaluate_expression(part))
                    if self.ret_val != None:
                        return self.ret_val
            else:
                self.ret_val = None
                self.interpret(self.evaluate_expression(code))
                if self.ret_val != None:
                    return self.ret_val
        elif expression.startswith("replace(") and expression.endswith(")"):
            expression = expression[8:-1]
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression)
            if len(parts) != 3:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 26
                    print(f"Error near line {self.current_line}: Invalid number of arguments for replace function.")
                    if self.fail:
                        sys.exit()
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
            return value.replace(old, new)
        elif any(expression.startswith(name) for name in self.structs.keys()) and "{" in expression and "}" in expression:
            name, args = expression[:-1].split("{", 1)
            rep_in_args = 0
            char_ = 0
            in_str = False
            args = list(args)
            for char in args:
                if char == "{" or char == "[":
                    rep_in_args += 1
                elif char == "}" or char == "]":
                    rep_in_args -= 1
                elif not in_str and char == '"':
                    in_str = True
                elif in_str and char == '"':
                    in_str = False
                elif (rep_in_args == 0 and char == "|" and not in_str) or (rep_in_args == 0 and char == "," and not in_str):
                    args[char_] = "$#@"
                char_ += 1
            args_body = ""
            for char in args:
                args_body+=char
            args = args_body

            args = list(filter(None, re.split(r'[\$\#\@]\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', args)))
            for i, arg in enumerate(args):
                args[i] = self.evaluate_expression(arg.strip()) if arg != "" else None

            name = name.strip()

            struct_def = self.structs[name]
            result = {}

            for i, (key, default_value) in enumerate(struct_def.items()):
                if i < len(args) and args[i] is not None:
                    result[key] = self.evaluate_expression(args[i]) if repr(args[i]).startswith("@") else args[i]
                else:
                    result[key] = self.evaluate_expression(default_value) if repr(default_value).startswith("@") else default_value

            #function stolen from https://stackoverflow.com/questions/2444680/how-do-i-add-my-own-custom-attributes-to-existing-built-in-python-types-like-a
            def attr(e,n,v): #will work for any object you feed it, but only that object
                class tmp(type(e)):
                    def attr(self,n,v):
                        setattr(self,n,v)
                        return self
                return tmp(e).attr(n,v)

            result = attr(result, "__type__", name)

            return result
        elif "+" in expression and self.add_or_str(expression) and not self.add_or_index(expression):
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
                    if self.fail:
                        sys.exit()
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
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 28
                return None
            regex_pattern = r"{}".format(regex_pattern) 
            if not isinstance(string_to_split, str):
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 29
                    print(f"Error near line {self.current_line}: The second argument of resplit() must be a string.")
                    if self.fail:
                        sys.exit()
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
                    if self.fail:
                        sys.exit()
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
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 31
        elif expression.startswith("splitby(") and expression.endswith(")"):
            args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[8:-1])
            if len(args) < 2:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 32
                    print(f"Error near line {self.current_line}: Invalid number of arguments for splitby function.")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 32
                return None
            char_to_split = self.evaluate_expression(args[0].strip())
            string_to_split = self.evaluate_expression(args[1].strip())
            if len(args) == 3:
                return string_to_split.split(char_to_split, self.evaluate_expression(args[2].strip()))
            else:
                return string_to_split.split(char_to_split)
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
            arg = self.evaluate_expression(expression[5:-1])
            try:
                type_ = arg.__type__
                return str(type_)
            except Exception:
                return str(type(arg).__name__)
        elif expression.startswith("len(") and expression.endswith(")"):
            return len(self.evaluate_expression(expression[4:-1].strip()))
        elif expression.startswith("splitlines(") and expression.endswith(")"):
            return self.variables[expression[11:-1]].splitlines()
        elif expression.startswith("file_read(") and expression.endswith(")"):
            file_path = self.evaluate_expression(expression[10:-1])
            try:
                with open(file_path, 'r') as file:
                    return file.read()
            except FileNotFoundError:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 33
                    print(f"Error near line {self.current_line}: File '{file_path}' not found.")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 33
                return ""
        elif expression.startswith("index(") and expression.endswith(")"):
            args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[6:-1])
            if len(args) != 2:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 34
                    print(f"Error near line {self.current_line}: Invalid number of arguments for index function.")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 34
                return None
            list_name = args[0].strip()
            value = args[1].strip()
            if list_name in self.variables and isinstance(self.variables[list_name], list):
                value = self.evaluate_expression(value.strip())
                try:
                    index_value = self.variables[list_name].index(value)
                    return index_value
                except ValueError:
                    if not self.in_try_block:
                        self.in_func_err()
                        self.variables["err"] = 35
                        print(f"Error near line {self.current_line}: Value '{value}' not found in list '{list_name}'.")
                        if self.fail:
                            sys.exit()
                    else:
                        self.variables["err"] = 35
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 36
                    print(f"Error near line {self.current_line}: Variable '{list_name}' is not a list.")
                    if self.fail:
                        sys.exit()
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
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 37
                return None
        elif expression.startswith("isanumber(") and expression.endswith(")"):
            expression = expression[10:-1]
            return str(self.evaluate_expression(expression)).isnumeric()
        elif expression.startswith("dirname(") and expression.endswith(")"):
            return os.path.dirname(self.evaluate_expression(expression[8:-1]))
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
            self.in_func.append(True)
            self.function_tracker.append(expression[1:].split("(")[0])
            self.ret_val = None
            self.interpret(expression)
            self.in_func.pop()
            self.function_tracker.pop()
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
        elif expression.startswith("call"):
            call_statement = expression[4:].strip()
            file_name, function_name, args = self.parse_call_statement(call_statement)
            return self.call_function_from_file(file_name, function_name, args)
        elif expression.startswith("ccall"):
            call_statement = expression[5:].strip()
            file_name, function_name, args = self.parse_call_statement(call_statement)
            return self.ccall_function_from_file(file_name, function_name, args)
        elif "." in expression:
            name, field = expression.split(".", 1)
            return self.acces_field(name, field)
        elif expression.startswith("&"):
            if expression[1:] in self.variables:
                return Reference(expression[1:])
            if expression[1:] in self.functions:
                return FuncReference(expression[1:])
        elif expression.startswith("*"):
            ref = self.evaluate_expression(expression[1:])
            if isinstance(ref, Reference):
                if ref.var_name in self.variables:
                    return self.variables[ref.var_name]
                else:
                    if not self.in_try_block:
                        self.in_func_err()
                        self.variables["err"] = 47
                        print(f"Error near line {self.current_line}: Referenced variable '{ref.var_name}' no longer exists")
                        if self.fail:
                            sys.exit()
                    else:
                        self.variables["err"] = 47
            else:
                return ref
        elif expression.startswith("fields(") and expression.endswith(")"):
            struct = self.evaluate_expression(expression[7:-1])
            return list(struct.keys())
        elif expression.startswith("is_func(") and expression.endswith(")"):
            value = self.evaluate_expression(expression[8:-1])
            return (
                isinstance(value, FuncReference)
                or isinstance(value, str) and value in self.functions
            )
        elif expression.startswith("ascii(") and expression.endswith(")"):
            return ord(self.evaluate_expression(expression[6:-1]))
        elif expression.startswith("~"):
            value = expression[1:]
            return lambda: self.evaluate_expression(value)
        elif expression in self.variables:
            if expression in self.locals:
                if self.locals[expression] == self.function_tracker[-1]:
                    return self.variables[expression]
                else:
                    if not self.in_try_block:
                        self.in_func_err()
                        self.variables["err"] = 46
                        print(f"Error near line {self.current_line}: Variable '{expression}' not found in current scope.")
                        if self.fail:
                            sys.exit()
                    else:
                        self.variables["err"] = 46
            else:
                return self.variables[expression]
        else:
            try:
                return eval(expression, {}, self.variables)
            except NameError:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 38
                    print(f"Error near line {self.current_line}: Unknown variable or expression: {expression}")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 38
        return None

    def acces_field(self, name, field):
        obj = self.variables[name.strip()]
        if isinstance(obj, Reference):
            obj = self.variables[obj.var_name]
        parts = re.findall(r'\w+|\[.*?\]', field)

        for part in parts:
            if part.startswith('['):
                index_expr = part[1:-1].strip()
                index = self.evaluate_expression(index_expr)
                obj = obj[index]
            else:
                obj = obj[part.strip()]
        return obj

    def assign_value(self, var_name, expression):
        value = self.evaluate_expression(expression)
        if isinstance(value, dict):
            value = value.copy()

        if var_name.startswith("*"):
            ref = self.evaluate_expression(var_name[1:].strip())
            if isinstance(ref, Reference):
                var_name = ref.var_name

        if "." in var_name:
            tokens = re.findall(r"[a-zA-Z_]\w*|\[\s*[^\]]+\s*\]", var_name)

            if not tokens:
                raise ValueError("Invalid struct field")

            var_name = tokens[0]
            if var_name not in self.variables:
                raise KeyError(f"Variable '{var_name}' not found")

            target = self.variables[var_name]
            if isinstance(target, Reference):
                target = self.variables[target.var_name]

            for token in tokens[1:-1]:
                if token.startswith('['):
                    index_expr = token[1:-1].strip()
                    index = self.evaluate_expression(index_expr)
                    target = target[index]
                else:
                    target = target[token]

            last_token = tokens[-1]
            if last_token.startswith('['):
                index_expr = last_token[1:-1].strip()
                index = self.evaluate_expression(index_expr)
                target[index] = value
            else:
                target[last_token] = value
        else:
            if '[' in var_name:
                base_var = var_name.split('[')[0]

                indexes = re.findall(r'\[(.*?)\]', var_name)

                target = self.variables[base_var]
                if isinstance(target, Reference):
                    target = self.variables[target.var_name]

                for index_expr in indexes[:-1]:
                    index = self.evaluate_expression(index_expr)
                    target = target[index]

                last_index = self.evaluate_expression(indexes[-1])
                target[last_index] = value
            else:
                self.variables[var_name] = value


    def print_value(self, value):
        char_ = 0
        prog = list(value)
        in_str = False
        depth = 0
        for char in prog:
            if char == '"':
                in_str = not in_str
            elif (char == "{") or (char == "[") or (char == "("):
                depth += 1
            elif (char == "}") or (char == "]") or (char == ")"):
                depth -= 1
            elif char == "," and depth == 0 and not in_str:
                prog[char_] = "&#$%^"
            char_ += 1
        value = "".join(prog)
        parts = value.split("&#$%^")
        part_count = 0
        for part in parts:
            parts[part_count] = self.evaluate_expression(parts[part_count].strip())
            if isinstance(parts[part_count], str):
                parts[part_count] = parts[part_count].replace("\\n", "\n")
            part_count += 1
        for part in parts:
            if not (self.in_try_block and part == None):
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
        start_val = self.evaluate_expression(start.strip())
        end_val = self.evaluate_expression(end.strip())

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
                self.variables["err"] = 39
                print(f"Error near line {self.current_line}: Invalid range expression for loop.")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 39

        self.break_stack.pop()

    def import_functions(self, file_path):
        file_path = file_path.strip('"')
    
        if file_path.startswith("https://") or file_path.startswith("http://"):
            import requests
            name = os.path.basename(file_path).split(".")[0]
            f = requests.get(file_path)
            program = f.text
            lines = self.preprocess(program)

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
            if "::" in file_path:
                args = file_path.split("::")
                file = args.pop()
                folder = "/".join(args)
                file_path = f"{PackageManager.user_packages_path}/{folder}/{file}.pryzma"
            else:
                file_path = f"{PackageManager.user_packages_path}/{file_path}/{file_path}.pryzma"
            self.load_functions_from_file(file_path)

    def load_function_from_file(self, file_path, func_name):
        name = os.path.splitext(os.path.basename(file_path))[0]
        try:
            with open(file_path, 'r') as file:
                program = file.read()
                lines = self.preprocess(program)

                function_def = False
                function_name = ""
                function_body = []
                match = False
                for line in lines:
                    if line.startswith("/"):
                        if line[1:].startswith(name + "."):
                            if self.nan:
                                line = "/" + line[len(name) + 2:]
                        match = line[1:].startswith(func_name+"{")
                        if match:
                            self.interpret(line)
        except FileNotFoundError:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 40
                print(f"Error near line {self.current_line}: File '{file_path}' not found.")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 40

    def load_functions_from_file(self, file_path):
        name = os.path.splitext(os.path.basename(file_path))[0]
        try:
            with open(file_path, 'r') as file:
                program = file.read()
                lines = self.preprocess(program)

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
                self.variables["err"] = 40
                print(f"Error near line {self.current_line}: File '{file_path}' not found.")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 40

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
                self.variables["err"] = 41
                print(f"Error near line {self.current_line}: List '{list_name}' does not exist.")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 41

    def pop_from_list(self, list_name, index):
        if list_name in self.variables:
            try:
                index = self.evaluate_expression(index)
                self.variables[list_name].pop(index)
            except IndexError:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variables["err"] = 42
                    print(f"Error near line {self.current_line}: Index {index} out of range for list '{list_name}'.")
                    if self.fail:
                        sys.exit()
                else:
                    self.variables["err"] = 42
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 43
                print(f"Error near line {self.current_line}: List '{list_name}' does not exist.")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 43

    def debug_interpret_func(self, line, current_line, breakpoints, log_message, print_help):
        self.in_func.append(True)
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
        self.function_tracker.append(function_name)
        if function_name in self.functions:
            command = 0
            continue_ = False
            while command < len(self.functions[function_name]):
                if continue_ == False:
                    command_ = input("Debugger> ").strip()
                    if command_ == 's':
                        log_message("User chose to step.")
                        log_message(f"Executing line {self.functions[function_name][command]}")
                        print(f"Debug: Executing line: {self.functions[function_name][command]}")
                        self.interpret(self.functions[function_name][command])
                        command += 1
                    elif command_ == 'c':
                        log_message("User chose to continue.")
                        continue_ = True
                    elif command_.startswith('b '):
                        try:
                            line_num = int(command_.split()[1])
                            breakpoints.add(line_num-1)
                            print(f"Breakpoint added at line {line_num}.")
                            log_message(f"Breakpoint added at line {line_num}.")
                        except ValueError:
                            print("Invalid line number. Usage: b <line_number>")
                    elif command_.startswith('r '):
                        try:
                            line_num = int(command_.split()[1])
                            breakpoints.discard(line_num)
                            print(f"Breakpoint removed at line {line_num}.")
                            log_message(f"Breakpoint removed at line {line_num}.")
                        except ValueError:
                            print("Invalid line number. Usage: r <line_number>")
                    elif command_ == 'l':
                        print("Breakpoints:", sorted(breakpoints))
                        log_message(f"Breakpoints listed: {sorted(breakpoints)}")
                    elif command_ == 'v':
                        print("Variables:", self.variables)
                        log_message(f"Variables: {self.variables}")
                    elif command_ == 'f':
                        print("Functions:", self.functions)
                        log_message(f"Functions: {self.functions}")
                    elif command_ == 'st':
                        print("Structs:", self.structs)
                        log_message(f"Structs: {self.structs}")
                    elif command_.startswith("!"):
                        self.interpret(command_[1:])
                        print("\n")
                        log_message(f"Run code: {command_[1:]}")
                    elif command_ == 'log':
                        self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                        print(f"Logging to {self.log_file}")
                        log_message(f"Log file set to: {self.log_file}")
                    elif command_ == 'exit':
                        print("Exiting debugger.")
                        log_message("Debugger exited.")
                        return
                    elif command_ == 'help':
                        print_help()
                    elif command_ == 'clear':
                        if os.name == "posix":
                            os.system('clear')
                        else:
                            os.system('cls')
                    else:
                        print("Unknown command. Type 'help' for a list of commands.")
                else:
                    log_message(f"Executing line {self.functions[function_name][command]}")
                    self.interpret(self.functions[function_name][command])
                    command += 1
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 3
                print(f"Error near line {current_line}: Function '{function_name}' is not defined.")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 3
        self.in_func.pop()
        self.function_tracker.pop()


    def debug_interpreter(self, file_path, running_from_file, arguments):
        current_line = 0
        breakpoints = set()
        self.log_file = None
        self.variables["argv"] = arguments
        self.variables["__file__"] = os.path.abspath(file_path)

        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        try:
            with open(file_path, 'r') as file:
                program = file.read()
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
            return

        lines = self.preprocess(program)

        commands_info = {
            's': 'Step to the next line',
            'c': 'Continue to the next breakpoint',
            'b <line>': 'Add a breakpoint at the specified line number',
            'r <line>': 'Remove a breakpoint at the specified line number',
            'l': 'List all current breakpoints',
            'v': 'View all variables',
            'f': 'View all functions',
            'st': 'View all structs',
            '! <pryzma code>': 'Run some pryzma code',
            'log': 'Set the log file name (default is log.txt)',
            'exit': 'Exit the debugger',
            'help': 'Show this help message'
        }

        def print_help():
            print("Available commands:")
            for cmd, desc in commands_info.items():
                print(f"{cmd}: {desc}")

        def log_message(message):
            if self.log_file:
                with open(self.log_file, 'a') as f:
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
                print("Variables:", self.variables)
                log_message(f"Variables: {self.variables}")
            elif command == 'f':
                print("Functions:", self.functions)
                log_message(f"Functions: {self.functions}")
            elif command == 'st':
                print("Structs:", self.structs)
                log_message(f"Structs: {self.structs}")
            elif command.startswith("!"):
                self.interpret(command[1:])
                print("\n")
                log_message(f"Run code: {command[1:]}")
            elif command == 'log':
                self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                print(f"Logging to {self.log_file}")
                log_message(f"Log file set to: {self.log_file}")
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
            
            if not line.startswith("//") and line != "":
                print(f"Debug: Executing line {current_line + 1}: {line}")
                log_message(f"Executing line {current_line + 1}: {line}")

                try:
                    if line.startswith("@"):
                        self.debug_interpret_func(line, current_line, breakpoints, log_message, print_help)
                    else:
                        self.interpret(line)
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
                        if not line.startswith("//") and line != "":
                            print(f"Debug: Executing line {current_line + 1}: {line}")
                            log_message(f"Executing line {current_line + 1}: {line}")

                            try:
                                if line.startswith("@"):
                                    self.debug_interpret_func(line, current_line, breakpoints, log_message, print_help)
                                else:
                                    self.interpret(line)
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
                    print("Variables:", self.variables)
                    log_message(f"Variables: {self.variables}")
                elif command == 'f':
                    print("Functions:", self.functions)
                    log_message(f"Functions: {self.functions}")
                elif command == 'st':
                    print("Structs:", self.structs)
                    log_message(f"Structs: {self.structs}")
                elif command.startswith("!"):
                    self.interpret(command[1:])
                    print("\n")
                    log_message(f"Run code: {command[1:]}")
                elif command == 'log':
                    self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                    print(f"Logging to {self.log_file}")
                    log_message(f"Log file set to: {self.log_file}")
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
            cvf = input("Clear variables, functions and staructs dictionaries? (y/n): ")
            if cvf.lower() == "y":
                self.variables.clear()
                self.functions.clear()
                self.structs.clear()


    def parse_call_statement(self, statement):
        if statement.startswith("(") and statement.endswith(")"):
            statement = statement[1:-1]
            parts = [part.strip() for part in re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', statement)]
            
            if len(parts) < 2:
                if not self.in_try_block:
                    self.in_func_err()
                    self.variabes["err"] = 44
                    print("Invalid number of arguments for call")
                else:
                    self.variables["err"] = 44
            
            file_name = self.evaluate_expression(parts[0])
            function_name = self.evaluate_expression(parts[1])
            
            args = parts[2:]
            
            for i, arg in enumerate(args):
                args[i] = self.evaluate_expression(arg)
            
            return file_name, function_name, args
        else:
            if not self.in_try_block:
                self.in_func_err()
                self.variables["err"] = 45
                print("Invalid call statement format. Expected format: call(file_name, function_name, arg1, arg2, ...)")
                if self.fail:
                    sys.exit()
            else:
                self.variables["err"] = 45

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
                return func(self, *args)
            else:
                print(f"'{function_name}' is not callable in '{file_name}'.")
        else:
            print(f"Function '{function_name}' is not defined in '{file_name}'.")

    def ccall_function_from_file(self, file_name, function_name, args):
        if not os.path.isfile(file_name):
            print(f"File '{file_name}' does not exist.")
            return

        c_functions = ctypes.CDLL(file_name)

        try:
            c_func = getattr(c_functions, function_name)
        except AttributeError:
            print(f"Function '{function_name}' not found in '{file_name}'.")
            return

        return c_func(*args)

    def print_help(self):
        print("""
commands:
    file - run a program from a file
    cls - clear the functions, variables and structs dictionaries
    clear - clear the console
    debug - start debugging mode
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
16 - Tkinter isn't enabled
17 - Invalid statement
18 - Unknown error
19 - Module does not have a 'start' function.
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
38 - Unknown variable or expression
39 - Invalid range expression for loop
40 - File not found for use function
41 - List does not exist for append function
42 - Index out of range for pop function
43 - List does not exist for pop function
44 - Invalid number of arguments for call.
45 - Invalid call statement format.
46 - Variable not found in current scope.
47 - Referenced variable no longer exists.
48 - Referenced function no longer exists.
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
            if len(user_input) < 1:
                continue
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
        interpreter.structs.clear()
    elif code == "clear":
        if os.name == "posix":
            os.system('clear')
        else:
            os.system('cls')
    elif code == "file":
        running_from_file = True
        interpreter.interpret_file2()
        cvf = input("Clear variables, functions and structs dictionaries? (y/n): ")
        if cvf.lower() == "y":
            interpreter.variables.clear()
            interpreter.functions.clear()
            interpreter.structs.clear()
        running_from_file = False
    elif code == "license":
        interpreter.show_license()
    elif code == "debug":
        running_from_file = True
        file_path = input("Path to the file to debug ('exit' to quit debug mode): ")
        if file_path != "exit":
            interpreter.debug_interpreter(file_path, running_from_file, [])
        running_from_file = False
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
        print("structs:", interpreter.structs, "\n")




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
    -s  - safe mode, disable a lot of potentialy dangerous keywords
    -pk - output a packed version of a given file to stdout (recomended ext is .prz)
    -upk - output an unpacked version of a given file to stdout
    -upi - unpack and interpret the given file (content of packed files is prefixed with prz so its automaticly recognized and this flag isn't needed most of the time)
                    """)
                    sys.exit()
                if arg == "-d":
                    arguments.remove(arg)
                    debug = True
                    interpreter.debug_interpreter(file_path, running_from_file, arguments)
                if arg == "-p":
                    interpreter.preprocess_only = True
                if arg == "-np":
                    interpreter.no_preproc = True
                if arg == "-l":
                    interpret_line = True
                if arg == "-fd":
                    interpreter.forward_declare = True
                if arg == "-s":
                    interpreter.deleted_keywords.extend(["call", "sys(", "mkdir", "makeidrs", "rmdir", "removedirs", "copy", "copyfile", "move", "rename", "remove", "symlink", "unlink", "file_read", "file_write", "load", "pyeval", "py{", "asm", "enablekeyword", "disablekeyword"])
                if arg == "-pk":
                    sys.stdout.buffer.write(interpreter.pack(file_path))
                    sys.exit()
                if arg == "-upk":
                    print(interpreter.unpack(file_path))
                    sys.exit()
                if arg == "-upi":
                    interpreter.unpack_ = True
                    arguments.remove(arg)
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
