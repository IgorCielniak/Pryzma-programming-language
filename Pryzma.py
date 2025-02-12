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
import requests


class PryzmaInterpreter:
    
    def __init__(self):
        self.variables = {}
        self.functions = {}
        self.tk_vars = {}
        self.custom_handlers = {}
        self.deleted_key_words = []
        self.variables["interpreter_path"] = __file__
        self.in_try_block = False
        self.in_func = False
        self.current_func_name = None


    def interpret_file(self, file_path, *args):
        self.file_path = file_path.strip('"')
        self.variables["pargs"] = args
        self.variables["file"] = os.path.abspath(file_path)
        try:
            with open(self.file_path, 'r') as file:
                program = file.read()
                self.interpret(program)
        except FileNotFoundError:
            print(f"File '{self.file_path}' not found.")

    def define_function(self, name, body):
        self.functions[name] = body

    def interpret(self, program):
        program = program.replace('&\n', '')
        program = program.replace('\n', ";")
        if not self.in_func:
            self.current_line = 0

        lines = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', program)
        lines = [stmt.strip() for stmt in lines if stmt.strip()]

        for line in lines:
            self.current_line += 1
            line = line.strip()
            
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
                    print(f"Error near line {self.curtent_line}: keyword deleted '{keyword}'")
                else:
                    self.variables["err"] = 1
                break

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
                elif line.startswith("for"):
                    loop_statement = line[len("for"):].strip()
                    loop_var = loop_statement.split(",")[0]
                    range_expr = loop_statement.split(",")[1]
                    actions = loop_statement.split(",")[2:]
                    loop_var = loop_var.strip()
                    range_expr = range_expr.strip()
                    for action in actions:
                        action = action.strip()
                    self.for_loop(loop_var, range_expr, actions)
                elif line.startswith("use"):
                    file_path = line[len("use"):].strip()
                    self.import_functions(file_path)
                elif line.startswith("if"):
                    line = line[2:]
                    line = line.split(".")
                    condition = line[0].strip()[1:-1]
                    action = line[1].strip()[1:-1]
                    if "==" in condition:
                        value1 = self.evaluate_expression(condition.split("==")[0])
                        value2 = self.evaluate_expression(condition.split("==")[1])
                        if value1 == value2:
                            self.interpret(action)
                    elif "!=" in condition:
                        value1 = self.evaluate_expression(condition.split("!=")[0])
                        value2 = self.evaluate_expression(condition.split("!=")[1])
                        if value1 != value2:
                            self.interpret(action)
                    elif "<=" in condition:
                        value1 = self.evaluate_expression(condition.split("<=")[0])
                        value2 = self.evaluate_expression(condition.split("<=")[1])
                        if value1 <= value2:
                            self.interpret(action)
                    elif ">=" in condition:
                        value1 = self.evaluate_expression(condition.split(">=")[0])
                        value2 = self.evaluate_expression(condition.split(">=")[1])
                        if value1 >= value2:
                            self.interpret(action)
                    elif "<" in condition:
                        value1 = self.evaluate_expression(condition.split("<")[0])
                        value2 = self.evaluate_expression(condition.split("<")[1])
                        if value1 < value2:
                            self.interpret(action)
                    elif ">" in condition:
                        value1 = self.evaluate_expression(condition.split(">")[0])
                        value2 = self.evaluate_expression(condition.split(">")[1])
                        if value1 > value2:
                            self.interpret(action)
                elif line.startswith("/"):
                    function_definition = line[1:].split("{")
                    if len(function_definition) == 2:
                        function_name = function_definition[0].strip()
                        function_body = function_definition[1].strip().rstrip("}")
                        function_body2 = function_body.split("|")
                        self.define_function(function_name, function_body2)
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
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
                            arg = arg.split(",")
                            for args in range(len(arg)):
                                arg[args] = arg[args].lstrip()
                            for args in range(len(arg)):
                                if arg[args].startswith('"') and arg[args].endswith('"'):
                                    arg[args] = arg[args][1:-1]
                                elif arg[args] in self.variables:
                                    arg[args] = self.variables[arg[args]]
                                elif arg[args].isdigit():
                                    arg[args] = int(arg[args])
                                else:
                                    if not self.in_try_block:
                                        self.in_func_err()
                                        print(f"Invalid argument at line {self.current_line}")
                                    else:
                                        self.variables["err"] = 3
                                    break
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
                            print(f"Error near line {self.current_line}: Function '{function_name}' is not defined.")
                        else:
                            self.variables["err"] = 4
                    self.in_func = False
                    self.cutrent_func_name = None
                elif line.startswith("interpret_pryzma(") and line.endswith(")"):
                    code = line[17:-1]
                    if "|" in code:
                        code = code.split("|")
                        for part in code:
                            if part.startswith('"') and part.endswith('"'):
                                part = part[1:-1]
                            else:
                                part = self.variables[part]
                            self.interpret(part)
                    else:
                        if code.startswith('"') and code.endswith('"'):
                            code = code[1:-1]
                        else:
                            code = self.variables[code]
                        self.interpret(code)
                elif line.startswith("try(") and line.endswith(")"):
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
                            print(f"Error near line {self.current_line}: Too much arguments")
                        else:
                            self.variables["err"] = 5
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
                            print(f"Error near line {self.current_line}: Too much arguments")
                        else:
                            self.variables["err"] = 6
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
                    self.variables[variable] = self.evaluate_expression(expression)
                elif line.startswith("copy"):
                    list1, list2 = line[len("copy"):].split(",")
                    list1 = list1.strip()
                    list2 = list2.strip()
                    for element in self.variables[list1]:
                        self.variables[list2].append(element)
                elif line.startswith("append"):
                    list_name, value = line[len("append"):].split(",")
                    list_name = list_name.strip()
                    value = value.strip()
                    self.append_to_list(list_name, value)
                elif line.startswith("pop"):
                    list_name, index = line[len("pop"):].split(",")
                    list_name = list_name.strip()
                    index = index.strip()
                    self.pop_from_list(list_name, index)
                elif line.startswith("remove"):
                    list_name, var = line[6:].split(",")
                    list_name = list_name.strip()
                    var = var.strip()
                    self.variables[list_name].remove(self.evaluate_expression(var))
                elif line.startswith("exec"):
                    line = line[4:].strip()
                    if line.startswith('"') and line.endswith('"'):
                        line = line[1:-1]
                    else:
                        line = self.variables[line]
                    os.system(line)
                elif line.startswith("write(") and line.endswith(")"):
                    file_path, content = line[6:-1].split(",")
                    file_path = file_path.strip()
                    content = content.strip()
                    if content.startswith('"') and content.endswith('"'):
                        content = content[1:-1]
                        if file_path.startswith('"') and file_path.endswith('"'):
                            file_path = file_path[1:-1]
                        self.write_to_file(content, file_path)
                    elif file_path.startswith('"') and file_path.endswith('"'):
                        file_path = file_path[1:-1]
                        if content.startswith('"') and content.endswith('"'):
                            content = content[1:-1]
                            self.write_to_file(content, file_path)
                        self.write_to_file(self.variables[content], file_path)
                    elif content in self.variables:
                        self.write_to_file(str(self.variables[content]), file_path)
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            print(f"Error near line {self.current_line}: Invalid content: {content}")
                        else:
                            self.variables["err"] = 7
                elif line.startswith("delvar(") and line.endswith(")"):
                    variable = line[7:-1]
                    if variable.startswith('"') and variable.endswith('"'):
                        variable = variable[1:-1]
                    else:
                        variable = self.variables[variable]
                    self.variables.pop(variable)
                elif line.startswith("delfunc(") and line.endswith(")"):
                    function = line[8:-1]
                    if function.startswith('"') and function.endswith('"'):
                        function = function[1:-1]
                    else:
                        function = self.variables[function]
                    self.functions.pop(function)
                elif line.startswith("delkeyword(") and line.endswith(")"):
                    key_word = line[11:-1] 
                    if key_word.startswith('"') and key_word.endswith('"'):
                        key_word = key_word[1:-1]
                    else:
                        key_word = self.variables[key_word]
                    self.deleted_key_words.append(key_word)
                elif line.startswith("whilen"):
                    condition_action = line[len("whilen"):].split(",", 2)
                    if len(condition_action) != 3:
                        if not self.in_try_block:
                            self.in_func_err()
                            print(f"Error near line {self.current_line}: Invalid while loop syntax. Expected format: while condition, value, action")
                        else:
                            self.variables["err"] = 8
                        continue
                    condition = condition_action[0].strip()
                    value = condition_action[1].strip()
                    action = condition_action[2].strip()
                    if (condition.startswith('"') and condition.endswith('"')) or (value.startswith('"') and value.endswith('"')):
                        while str(self.evaluate_expression(condition)) == str(self.evaluate_expression(value)):
                            self.interpret(action)
                    else:
                        while str(self.variables[condition]) != str(self.variables[value]):
                            self.interpret(action)
                elif line.startswith("while"):
                    condition_action = line[len("while"):].split(",", 2)
                    if len(condition_action) != 3:
                        if not self.in_try_block:
                            self.in_func_err()
                            print(f"Error near line {self.current_line}: Invalid while loop syntax. Expected format: while condition, value, action")
                        else:
                            self.variables["err"] = 9
                        continue
                    condition = condition_action[0].strip()
                    value = condition_action[1].strip()
                    action = condition_action[2].strip()
                    if (condition.startswith('"') and condition.endswith('"')) or (value.startswith('"') and value.endswith('"')):
                        while str(self.evaluate_expression(condition)) == str(self.evaluate_expression(value)):
                            self.interpret(action)
                    else:
                        while str(self.variables[condition]) == str(self.variables[value]):
                            self.interpret(action)
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
                            print(f"Error near line {self.current_line}: Invalid move instruction syntax. Expected format: move(old index, new index, list name)")
                        else:
                            self.variables["err"] = 10
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
                            print(f"Error near line {self.current_line}: Invalid index")
                        else:
                            self.variables["err"] = 11
                elif line.startswith("swap(") and line.endswith(")"):
                    instructions = line[5:-1].split(",")
                    if len(instructions) != 3:
                        if not self.in_try_block:
                            self.in_func_err()
                            print(f"Error near line {self.current_line}: Invalid swap instruction syntax. Expected format: swap(index 1, index 2, list name)")
                        else:
                            self.variables["err"] = 12
                        continue
                    list_name = instructions[2].strip()
                    index_1 = int(instructions[0].strip())
                    index_2 = int(instructions[1].strip())
                    if index_1 in self.variables:
                        index_1 = self.variables[index_1]
                    if index_2 in self.variables:
                        index_2 = self.variables[index_2]
                    try:
                        self.variables[list_name][index_1], self.variables[list_name][index_2] = self.variables[list_name][index_2], self.variables[list_name][index_1]
                    except ValueError:
                        if not self.in_try_block:
                            self.in_func_err()
                            print("Invalid index")
                        else:
                            self.variables["err"] = 13
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
                                    print(f"Error near line {self.current_line}: Invalid create_button command")
                                else:
                                    self.variables["err"] = 14
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
                                    print(f"Error near line {self.current_line}: Invalid create_label command")
                                else:
                                    self.variables["err"] = 15
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
                                    print(f"Error near line {self.current_line}: Invalid create_entry command")
                                else:
                                    self.variables["err"] = 16
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
                                    print(f"Error near line {self.current_line}: Invalid get_entry_text command")
                                else:
                                    self.variables["err"] = 17
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
                                    print(f"Error near line {self.current_line}: Invalid set_entry_text command")
                                else:
                                    self.variables["err"] = 18
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            print(f"Error near line {self.current_line}: tkinter isn't enabled")
                        else:
                            self.variables["err"] = 19
                elif line.startswith("call"):
                    call_statement = line[len("call"):].strip()
                    file_name, function_name, args = self.parse_call_statement(call_statement)
                    self.call_function_from_file(file_name, function_name, args)
                elif line.startswith("replace(") and line.endswith(")"):
                    args = line[8:-1].split(",")
                    if len(args) != 3:
                        if not self.in_try_block:
                            self.in_func_err()
                            print(f"Error near line {self.current_line}: Invalid number of arguments for replace function.")
                        else:
                            self.variables["err"] = 20
                        continue
                    string = self.variables[args[0]]
                    if args[1].startswith('"') and args[1].endswith('"'):
                        old = args[1][1:-1]
                    else:
                        old = self.variables[args[1]]
                    if args[2].startswith('"') and args[2].endswith('"'):
                        new= args[2][1:-1]
                    else:
                        new = self.variables[args[2]]
                    string = string.replace(old,new)
                    self.variables[args[0]] = string
                elif line.startswith("load(") and line.endswith(")"):
                    module_path = line[5:-1]
                    if module_path.startswith('"') and module_path.endswith('"'):
                        module_path = module_path[1:-1]
                    else:
                        module_path = self.variables[module_path]
                    self.load_module(module_path)
                elif line.startswith("wait(") and line.endswith(")"):
                    time_to_wait = float(line[5:-1])
                    time.sleep(time_to_wait)
                elif line == "stop":
                    input("Press any key to continue...")
                    break
                else:
                    if line == "" or line.startswith("#"):
                        continue
                    else:
                        if not handled:
                            if self.in_try_block:
                                self.variables["err"] = 21
                            else:
                                self.in_func_err()
                                print(f"Invalid statement at line {self.current_line}: {line}")
            except Exception as e:
                if self.in_try_block:
                    self.variables["err"] = 22
                else:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: {e}")

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
                    print(f"Module '{module_name}' does not have a 'start' function.")
                else:
                    self.variables["err"] = 23
        except Exception as e:
            if not self.in_try_block:
                self.in_func_err()
                print(f"Error loading module '{module_path}': {e}")
            else:
                self.variables["err"] = 24

    def decrement_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int):
                self.variables[variable] -= 1
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Cannot decrement non-integer variable '{variable}'.")
                else:
                    self.variables["err"] = 25
        else:
            if not self.in_try_block:
                self.in_func_err()
                print(f"Error near line {self.current_line}: Variable '{variable}' not found.")
            else:
                self.variables["err"] = 26

    def increment_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int):
                self.variables[variable] += 1
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Cannot increment non-integer variable '{variable}'.")
                else:
                    self.variables["err"] = 27
        else:
            if not self.in_try_block:
                self.in_func_err()
                print(f"Error near line {self.current_line}: Variable '{variable}' not found.")
            else:
                self.variables["err"] = 28


    def write_to_file(self, content, file_path):
        try:
            with open(file_path, 'w+') as file:
                if isinstance(content, list):
                    for line in content:
                        file.write(f"{line}\n")
                else:
                    file.write(content)
        except Exception as e:
            if not self.in_try_block:
                self.in_func_err()
                print(f"Error near line {self.current_line} while writing to file '{file_path}': {e}")
            else:
                self.variables["err"] = 29

    def evaluate_expression(self, expression):
        if re.match(r"^\d+$", expression):
            return int(expression)
        elif re.match(r'^".*"$', expression):
            return expression[1:-1]
        elif "+" in expression:
            parts = expression.split("+")
            evaluated_parts = [self.evaluate_expression(part.strip()) for part in parts]

            if all(isinstance(part, str) for part in evaluated_parts):
                return "".join(evaluated_parts)
            elif all(isinstance(part, (int, float)) for part in evaluated_parts):
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
            return str(type(self.variables[expression[5:-1]]))
        elif expression.startswith("len(") and expression.endswith(")"):
            return len(self.variables[expression[4:-1]])
        elif expression.startswith("splitby(") and expression.endswith(")"):
            args = expression[8:-1].split(",")
            if len(args) != 2:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Invalid number of arguments for splitby function.")
                else:
                    self.variables["err"] = 30
                return None
            char_to_split = args[0].strip()
            string_to_split = args[1].strip()
            if string_to_split in self.variables:
                string_to_split = self.variables[string_to_split]
            if char_to_split in self.variables:
                char_to_split = self.variables[char_to_split]
            if char_to_split.startswith('"') and char_to_split.endswith('"'):
                char_to_split = char_to_split[1:-1]
            if string_to_split.startswith('"') and string_to_split.endswith('"'):
                string_to_split = string_to_split[1:-1]
            return string_to_split.split(char_to_split)
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
            file_path = expression[5:-1]
            if file_path.startswith('"') and file_path.endswith('"'):
                file_path = file_path[1:-1]
            else:
                file_path = self.variables[file_path]
            try:
                with open(file_path, 'r') as file:
                    return file.read()
            except FileNotFoundError:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: File '{file_path}' not found.")
                else:
                    self.variables["err"] = 31
                return ""
        elif expression.startswith("in(") and expression.endswith(")"):
            list_name, value = expression[3:-1].split(",")
            list_name = list_name.strip()
            value = value.strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
                return value in self.variables[list_name]
            elif value.isnumeric():
                return int(value) in self.variables[list_name]
            elif value in self.variables:
                return self.variables[value] in self.variables[list_name]
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Variable '{value}' is not defined.")
                else:
                    self.variables["err"] = 32
        elif expression.startswith("index(") and expression.endswith(")"):
            args = expression[6:-1].split(",")
            if len(args) != 2:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Invalid number of arguments for index function.")
                else:
                    self.variables["err"] = 33
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
                        print(f"Error near line {self.current_line}: Value '{value}' not found in list '{list_name}'.")
                    else:
                        self.variables["err"] = 34
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Variable '{list_name}' is not a list.")
                else:
                    self.variables["err"] = 35
        elif expression.startswith("all(") and expression.endswith(")"):
            list_name = expression[4:-1]
            if list_name in self.variables and isinstance(self.variables[list_name], list):
                return " ".join(map(str, self.variables[list_name]))
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: List '{list_name}' is not defined.")
                else:
                    self.variables["err"] = 36
                return None
        elif expression.startswith("isanumber(") and expression.endswith(")"):
            expression = expression[10:-1]
            if expression in self.variables:
                expression = self.variables[expression]
                return str(expression).isnumeric()
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Variable '{expression}' is not defined.")
                else:
                    self.variables["err"] = 37
                return None
        elif expression.startswith("dir(") and expression.endswith(")"):
            expression = expression[4:-1]
            if expression.startswith('"') and expression.endswith('"'):
                return os.path.dirname(expression[1:-1])
            elif expression in self.variables:
                return os.path.dirname(self.variables[expression])
            else:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Invalid argument for dir() function")
                else:
                    self.variables["err"] = 38
                return None
        elif expression == "timenow":
            return datetime.datetime.now()
        elif expression in self.variables:
            return self.variables[expression]
        else:
            try:
                return eval(expression, {}, self.variables)
            except NameError:
                if not self.in_try_block:
                    self.in_func_err()
                    print(f"Error near line {self.current_line}: Unknown variable or expression: {expression}")
                else:
                    self.variables["err"] = 39
        return None

    def print_value(self, value):
        evaluated_value = self.evaluate_expression(value)
        if evaluated_value is not None:
            if isinstance(evaluated_value, str) and '\\n' in evaluated_value:
                print(evaluated_value.replace('\\n', '\n'))
            else:
                print(evaluated_value)

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
        
        if isinstance(start_val, int) and isinstance(end_val, int):
            for val in range(start_val, end_val):
                self.variables[loop_var] = val
                for action in actions:
                    self.interpret(action)
        else:
            if not self.in_try_block:
                self.in_func_err()
                print(f"Error near line {self.current_line}: Invalid range expression for loop.")
            else:
                self.variables["err"] = 40

    def import_functions(self, file_path):
        file_path = file_path.strip('"')
        
        if '/' in file_path or '\\' in file_path:
            self.load_functions_from_file(file_path)
        else:
            file_path = f"{PackageManager.user_packages_path}/{file_path}/{file_path}.pryzma"
            self.load_functions_from_file(file_path)

    def load_functions_from_file(self, file_path):
        try:
            with open(file_path, 'r') as file:
                program = file.read()
                lines = program.split('\n')
                function_def = False
                function_name = ""
                function_body = []
                for line in lines:
                    line = line.strip()
                    if line.startswith("/"):
                        if function_def:
                            self.define_function(function_name, function_body)
                            function_def = False
                        function_definition = line[1:].split("{")
                        if len(function_definition) == 2:
                            function_name = function_definition[0].strip()
                            function_body = function_definition[1].strip().rstrip("}").split("|")
                            function_def = True
                        else:
                            if not self.in_try_block:
                                self.in_func_err()
                                print(f"Error near line {self.current_line}: Invalid function definition in imported file: {line}")
                            else:
                                self.variables["err"] = 41
                    elif line.startswith("") or line.startswith("#"):
                        continue
                    else:
                        if not self.in_try_block:
                            self.in_func_err()
                            print(f"Error near line {self.current_line}: Invalid statement in imported file: {line}")
                        else:
                            self.variables["err"] = 42
                if function_def:
                    self.define_function(function_name, function_body)
        except FileNotFoundError:
            if not self.in_try_block:
                self.in_func_err()
                print(f"Error near line {self.current_line}: File '{file_path}' not found.")
            else:
                self.variables["err"] = 43

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
        if list_name in self.variables:
            self.variables[list_name].append(self.evaluate_expression(value))
        else:
            if not self.in_try_block:
                self.in_func_err()
                print(f"Error near line {self.current_line}: List '{list_name}' does not exist.")
            else:
                self.variables["err"] = 44

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
                    print(f"Error near line {self.current_line}: Index {index} out of range for list '{list_name}'.")
                else:
                    self.variables["err"] = 45
        else:
            if not self.in_tru_block:
                self.in_func_err()
                print(f"Error near line {self.current_line}: List '{list_name}' does not exist.")
            else:
                self.variables["err"] = 46


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
        self.variables["pargs"] = arguments
        self.variables["file"] = os.path.abspath(file_path)

        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        try:
            with open(file_path, 'r') as file:
                program = file.read()
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
            return

        program = program.replace('&\n', '')
        program = program.replace('\n', ";")

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

                print("Variables:", interpreter.variables)
                print("Functions:", interpreter.functions)
                log_message(f"Variables: {interpreter.variables}")
                log_message(f"Functions: {interpreter.functions}")

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

                            print("Variables:", interpreter.variables)
                            print("Functions:", interpreter.functions)
                            log_message(f"Variables: {interpreter.variables}")
                            log_message(f"Functions: {interpreter.functions}")
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
                    print("Invalid call statement format. Expected format: call(file_name, function_name, arg1, arg2, ...)")
                else:
                    self.variables["err"] = 1
            
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
                print("Invalid call statement format. Expected format: call(file_name, function_name, arg1, arg2, ...)")
            else:
                self.variables["err"] = 1

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
3 - Invalid argument
4 - Function not defined
5 - Too much arguments for +=
6 - Too much arguments for -=
7 - Invalid content for write()
8 - Invalid syntax for while
9 - Invalid syntax for whilen
10 - Invalid move() instruction syntax
11 - Invalid index for move() instruction
12 - Invalid swap() instruction syntax
13 - Invalid index for swap() instruction
14 - Invalid create_button command
15 - Invalid create_label command
16 - Invalid create_entry command
17 - Invalid get_entry_text command
18 - Invalid set_entry_text command
19 - Tkintet isn't enabled
20 - Invalid number of arguments for replace().
21 - Invalid statement
22 - Unknown error
23 - Module does not have a 'start' function."
24 - Error loading module
25 - Cannot decrement non-integer variable
26 - Variable not found for decrement function
27 - Cannot increment non-integer variable
28 - Variable noy found fot increment function
29 - Error writing to file
30 - Invalid number of arguments for splitby function
31 - File not found
32 - Variable not defined for in()
33 - Invalid number of arguments for index function 
34 - Value not found in list for index function
35 - Variable is not a list for index function
36 - List not defined for all()
37 - Variable is not defined for isanumber()
38 - Invalid argument for dir()
39 - Unknown variable or expression
40 - Invalid range expression for loop
41 - Invalid function definition in imported file
42 - Invalid statement in imported file
43 - File not found for use function 
44 - List does not exist for append function
45 - Index out of range for pop function
46 - List does not exist for pop function
""" 
)


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








if __name__ == "__main__":
    interpreter = PryzmaInterpreter()

    tkinter_enabled = False
    history = []
    running_from_file = False
    version = 5.5

    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        arguments = sys.argv[1:]
        debug = False
        for arg in arguments:
            if arg.startswith("-"):
                if arg == "-d":
                    arguments.remove(arg)
                    debug = True
                    interpreter.debug_interpreter(interpreter, file_path, running_from_file, arguments)
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
