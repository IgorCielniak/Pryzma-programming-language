import re
import sys
import os
import importlib.util
import datetime
import json
import urllib.request
import shutil
import zipfile

class PryzmaInterpreter:
    
    def __init__(self):
        self.variables = {}
        self.functions = {}
        self.tk_vars = {}

    def interpret_file(self, file_path, *args):
        self.file_path = file_path.strip('"')
        arg_count = 0
        for arguments in args:
            self.variables[f"parg{arg_count}"] = args[arg_count]
            arg_count += 1
        try:
            with open(self.file_path, 'r') as file:
                program = file.read()
                self.interpret(program)
        except FileNotFoundError:
            print(f"File '{self.file_path}' not found.")

    def define_function(self, name, body):
        self.functions[name] = body

    def interpret(self, program):
        lines = program.split('\n')
        self.current_line = 0
        
        for line in lines:
            self.current_line += 1
            line = line.strip()

            try:
                if line.startswith("print"):
                    value = line[len("print"):].strip()
                    self.print_value(value)
                elif line.startswith("input"):
                    variable = line[len("input"):].strip()
                    self.custom_input(variable)
                elif line.startswith("for"):
                    loop_statement = line[len("for"):].strip()
                    loop_var, range_expr, action = loop_statement.split(",", 2)
                    loop_var = loop_var.strip()
                    range_expr = range_expr.strip()
                    action = action.strip()
                    self.for_loop(loop_var, range_expr, action)
                elif line.startswith("use"):
                    file_path = line[len("use"):].strip()
                    self.import_functions(file_path)
                elif line.startswith("ifs"):
                    condition_actions = line[len("ifs"):].split(",")
                    if len(condition_actions) != 3:
                        print("Invalid if instruction. Expected format: ifs condition, value, action")
                        continue
                    condition = condition_actions[0].strip()
                    value = condition_actions[1].strip()
                    action = condition_actions[2].strip()
                    if condition.startswith('"') and condition.endswith('"'):
                        condition = condition[1:-1]
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    if value in self.variables:
                        value = self.variables[value]
                    if condition in self.variables:
                        condition = self.variables[condition]
                    if condition == "*" or action == "*":
                        self.interpret(action)
                    elif value > condition:
                        self.interpret(action)
                elif line.startswith("ifb"):
                    condition_actions = line[len("ifb"):].split(",")
                    if len(condition_actions) != 3:
                        print("Invalid if instruction. Expected format: ifb condition, value, action")
                        continue
                    condition = condition_actions[0].strip()
                    value = condition_actions[1].strip()
                    action = condition_actions[2].strip()
                    if condition.startswith('"') and condition.endswith('"'):
                        condition = condition[1:-1]
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    if value in self.variables:
                        value = self.variables[value]
                    if condition in self.variables:
                        condition = self.variables[condition]
                    if condition == "*" or action == "*":
                        self.interpret(action)
                    elif value < condition:
                        self.interpret(action)
                elif line.startswith("ifn"):
                    condition_actions = line[len("ifn"):].split(",")
                    if len(condition_actions) != 3:
                        print("Invalid if instruction. Expected format: ifn condition, value, action")
                        continue
                    condition = condition_actions[0].strip()
                    value = condition_actions[1].strip()
                    action = condition_actions[2].strip()
                    if condition.startswith('"') and condition.endswith('"'):
                        condition = condition[1:-1]
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    if value in self.variables:
                        value = self.variables[value]
                    if condition in self.variables:
                        condition = self.variables[condition]
                    if condition == "*" or action == "*":
                        self.interpret(action)
                    elif value != condition:
                        self.interpret(action)
                elif line.startswith("if"):
                    condition_actions = line[len("if"):].split(",")
                    if len(condition_actions) != 3:
                        print("Invalid if instruction. Expected format: if condition, value, action")
                        continue
                    condition = condition_actions[0].strip()
                    value = condition_actions[1].strip()
                    action = condition_actions[2].strip()
                    if condition.startswith('"') and condition.endswith('"'):
                        condition = condition[1:-1]
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    if value in self.variables:
                        value = self.variables[value]
                    if condition in self.variables:
                        condition = self.variables[condition]
                    if condition == "*" or action == "*":
                        self.interpret(action)
                    elif value == condition:
                        self.interpret(action)
                elif line.startswith("/"):
                    self.variable_definition_in_function_body = "no"
                    function_definition = line[1:].split("{")
                    if len(function_definition) == 2:
                        function_name = function_definition[0].strip()
                        function_body = function_definition[1].strip().rstrip("}")
                        function_body2 = function_body.split("|")
                        self.define_function(function_name, function_body2)
                    else:
                        print(f"Invalid function definition: {line}")
                elif line.startswith("@"):
                    function_name = line[1:].strip()
                    if "(" in function_name:
                        function_name, arg = function_name.split("(") 
                        arg = arg.strip(")")
                        if arg:
                            arg = arg.split(",")
                            for args in range(len(arg)):
                                arg[args] = arg[args].lstrip()
                            for args in range(len(arg)):
                                if arg[args].startswith('"') and arg[args].endswith('"'):
                                    self.variables[f'arg{args+1}'] = arg[args][1:-1]
                                elif arg[args] in self.variables:
                                    self.variables[f'arg{args+1}'] = self.variables[arg[args]]
                                elif arg[args].isdigit():
                                    self.variables[f'arg{args+1}'] = int(arg[args])
                                else:
                                    print(f"Invalid argument at line {self.current_line}")
                                    break
                    if function_name in self.functions:
                        command = 0
                        while command < len(self.functions[function_name]):
                            self.interpret(self.functions[function_name][command])
                            command += 1
                    else:
                        print(f"Function '{function_name}' is not defined.")
                elif "=" in line:
                    variable, expression = line.split('=')
                    variable = variable.strip()
                    expression = expression.strip()
                    self.assign_variable(variable, expression)
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
                elif line.startswith("exec"):
                    line = line[5:]
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
                        print(f"Invalid content at line {self.current_line}: {content}")
                elif line.startswith("del(") and line.endswith(")"):
                    variable = line[4:-1]
                    self.variables.pop(variable)
                elif line.startswith("whilen"):
                    condition_action = line[len("whilen"):].split(",", 2)
                    if len(condition_action) != 3:
                        print("Invalid while loop syntax. Expected format: while condition, value, action")
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
                        print("Invalid while loop syntax. Expected format: while condition, value, action")
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
                        print("Invalid move instruction syntax. Expected format: move(old index, new index, list name)")
                        continue
                    list_name = instructions[2].strip()
                    try:
                        old_index = int(instructions[0])
                        new_index = int(instructions[1])
                        value = self.variables[list_name].pop(old_index)
                        self.variables[list_name].insert(new_index, value)
                    except ValueError:
                        print("Invalid index")
                elif line.startswith("swap(") and line.endswith(")"):
                    instructions = line[5:-1].split(",")
                    if len(instructions) != 3:
                        print("Invalid swap instruction syntax. Expected format: swap(index 1, index 2, list name)")
                        continue
                    list_name = instructions[2].strip()
                    index_1 = instructions[0].strip()
                    index_2 = instructions[1].strip()
                    if index_1 in self.variables:
                        index_1 = self.variables[index_1]
                    if index_2 in self.variables:
                        index_2 = self.variables[index_2]
                    try:
                        self.variables[list_name][index_1], self.variables[list_name][index_2] = self.variables[list_name][index_2], self.variables[list_name][index_1]
                    except ValueError:
                        print("Invalid index")
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
                                self.tk_vars[button_name] = tk.Button(self.tk_vars[window],text = button_text,command = lambda: self.button_command_exec(button_command))
                            else:
                                print(f"Invalid create_button command")
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
                                print(f"Invalid create_label command")
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
                                print(f"Invalid create_entry command")
                            self.tk_vars[entry_name].pack()
                        elif command.startswith("get_entry_text(") and command.endswith(")"):
                            command = command[15:-1]
                            command = command.split(",")
                            entry_name = command[0].lstrip()
                            variable_name = command[1].lstrip()
                            if entry_name in self.tk_vars:
                                self.variables[variable_name] = self.tk_vars[entry_name].get()
                            else:
                                print(f"Invalid get_entry_text command")
                        elif command.startswith("set_entry_text(") and command.endswith(")"):
                            command = command[15:-1]
                            command = command.split(",")
                            entry_name = command[0].lstrip()
                            variable_name = command[1].lstrip()
                            if entry_name in self.tk_vars:
                                self.tk_vars[entry_name].delete(0, tk.END)
                                self.tk_vars[entry_name].insert(0, self.variables[variable_name])
                            else:
                                print(f"Invalid set_entry_text command")
                    else:
                        print("tkinter isn't enabled")
                elif line.startswith("call"):
                    call_statement = line[len("call"):].strip()
                    file_name, function_name = self.parse_call_statement(call_statement)
                    self.call_function_from_file(file_name, function_name)
                elif line == "stop":
                    input("Press any key to continue...")
                    break
                else:
                    if line == "" or line.startswith("#"):
                        continue
                    else:
                        print(f"Invalid statement at line {self.current_line}: {line}")
            except Exception as e:
                print(f"Error at line {self.current_line}: {e}")

    def button_command_exec(self, button_command):
        self.interpret(button_command)

    def decrement_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int):
                self.variables[variable] -= 1
            else:
                print(f"Error: Cannot decrement non-integer variable '{variable}'.")
        else:
            print(f"Error: Variable '{variable}' not found.")

    def increment_variable(self, variable):
        if variable in self.variables:
            if isinstance(self.variables[variable], int):
                self.variables[variable] += 1
            else:
                print(f"Error: Cannot increment non-integer variable '{variable}'.")
        else:
            print(f"Error: Variable '{variable}' not found.")


    def write_to_file(self, content, file_path):
        try:
            with open(file_path, 'w+') as file:
                if isinstance(content, list):
                    for line in content:
                        file.write(f"{line}\n")
                else:
                    file.write(content)
        except Exception as e:
            print(f"Error writing to file '{file_path}': {e}")

    def assign_variable(self, variable, expression):
        self.variables[variable] = self.evaluate_expression(expression)

    def evaluate_expression(self, expression):
        if "+" in expression:
            parts = expression.split("+")
            evaluated_parts = [self.evaluate_expression(part.strip()) for part in parts]
            if all(isinstance(part, int) for part in evaluated_parts):
                return sum(evaluated_parts)
            elif all(isinstance(part, str) for part in evaluated_parts):
                return "".join(evaluated_parts)
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
                print("Invalid number of arguments for splitby function.")
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
                print(f"File '{file_path}' not found.")
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
                print(f"Variable '{value}' is not defined.")
        elif expression.startswith("index(") and expression.endswith(")"):
            args = expression[6:-1].split(",")
            if len(args) != 2:
                print("Invalid number of arguments for index function.")
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
                    print(f"Value '{value}' not found in list '{list_name}'.")
            else:
                print(f"Variable '{list_name}' is not a list.")
        elif expression.startswith("all(") and expression.endswith(")"):
            list_name = expression[4:-1]
            if list_name in self.variables and isinstance(self.variables[list_name], list):
                return " ".join(map(str, self.variables[list_name]))
            else:
                print(f"List '{list_name}' is not defined.")
                return None
        elif expression.startswith("isanumber(") and expression.endswith(")"):
            expression = expression[10:-1]
            if expression in self.variables:
                expression = self.variables[expression]
                return str(expression).isnumeric()
            else:
                print(f"Variable '{expression}' is not defined.")
                return None
        elif expression == "timenow":
            return datetime.datetime.now()
        elif re.match(r"^\d+$", expression):
            return int(expression)
        elif re.match(r'^".*"$', expression):
            return expression[1:-1]
        elif expression in self.variables:
            return self.variables[expression]
        else:
            try:
                return eval(expression, {}, self.variables)
            except NameError:
                print(f"Unknown variable or expression: {expression}")
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

    def for_loop(self, loop_var, range_expr, action):
        start, end = range_expr.split(":")
        start_val = self.evaluate_expression(start)
        end_val = self.evaluate_expression(end)
        
        if isinstance(start_val, int) and isinstance(end_val, int):
            for val in range(start_val, end_val + 1):
                self.variables[loop_var] = val
                self.interpret(action)
        else:
            print("Invalid range expression for loop.")

    def import_functions(self, file_path):
        file_path = file_path.strip('"')
        
        if file_path.startswith("./"):
            if running_from_file == True:
                current_directory = os.path.dirname(self.file_path)
                absolute_file_path = os.path.join(current_directory, file_path[2:])
                self.load_functions_from_file(absolute_file_path)
            else:
                print("Cannot import functions from a relative path when running from the interpreter.")
        elif '/' in file_path or '\\' in file_path:
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
                            print(f"Invalid function definition: {line}")
                    elif line.startswith("") or line.startswith("#"):
                        continue
                    else:
                        print(f"Invalid statement in imported file: {line}")
                if function_def:
                    self.define_function(function_name, function_body)
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")

    def get_input(self, prompt):
        if sys.stdin.isatty():
            return input(prompt)
        else:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            return sys.stdin.readline().rstrip('\n')

    def evaluate_condition(self, condition):
        if condition in self.variables:
            return bool(self.variables[condition])
        else:
            print(f"Unknown variable in condition: {condition}")
            return False

    def interpret_file2(self):
        self.file_path = input("Enter the file path of the program: ")
        self.interpret_file(self.file_path)

    def show_license(self):
        license_text = """
Pryzma
Copyright 2024 Igor Cielniak

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
            print(f"List '{list_name}' does not exist.")

    def pop_from_list(self, list_name, index):
        if list_name in self.variables:
            try:
                if index.isnumeric():
                    index = int(index)
                else:
                    index = self.variables[index]
                self.variables[list_name].pop(index)
            except IndexError:
                print(f"Index {index} out of range for list '{list_name}'.")
                return
        else:
            print(f"List '{list_name}' does not exist.")


    def execute_function_from_file(self):
        file_path = input("Enter the file path of the function: ")
        function_name = input("Enter the function name: ")
        self.import_functions(file_path)
        if function_name in self.functions:
            for line in self.functions[function_name]:
                self.interpret(line)
        else:
            print(f"Function '{function_name}' is not defined in '{file_path}'.")

    def debug_interpreter(interpreter, file_path):
        current_line = 0
        breakpoints = set()
        log_file = None

        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
            return

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
                else:
                    print("Unknown command. Type 'help' for a list of commands.")


    def parse_call_statement(self, statement):
        if statement.startswith("(") and statement.endswith(")"):
            statement = statement[1:-1]
            file_name, function_name = statement.split(",")
            file_name = file_name.strip()
            function_name = function_name.strip()
            if file_name.startswith('"') and file_name.endswith('"'):
                file_name = file_name[1:-1]
            if function_name.startswith('"') and function_name.endswith('"'):
                function_name = function_name[1:-1]
            return file_name.strip(), function_name.strip()
        else:
            raise ValueError("Invalid call statement format. Expected format: call(file_name, function_name)")

    def call_function_from_file(self, file_name, function_name):
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
                func()
            else:
                print(f"'{function_name}' is not callable in '{file_name}'.")
        else:
            print(f"Function '{function_name}' is not defined in '{file_name}'.")







    def print_help(self):
        print("""
commands:
        file - run a program from a file
        cls - clear the functions and variables dictionaries
        clst - set clearing functions and variables dictionaries after program execution to true
        clsf - set clearing functions and variables dictionaries after program execution to false
        clear - clear the console
        debug - start debugging mode
        func - execute a function from a file
        history - show the commands history
        history <number> - execute the command from the history by number
        history clear - clear the commands history
        history <term> - search the commands history for a term
        cmd <command> - execute a command in the operating system shell
        cmd - start the operating system shell
        exit - exit the interpreter
        help - show this help
        license - show the license
""")


class PackageManager:
    user_packages_path = os.path.dirname(sys.argv[0]) + "/packages/"
    package_urls = {
        "math": "https://github.com/IgorCielniak/Pryzma-packages/archive/refs/heads/math.zip",
        "std": "https://github.com/IgorCielniak/Pryzma-packages/archive/refs/heads/std.zip"
    }

    def initialize_repository(self):
        if not os.path.exists(self.user_packages_path):
            os.makedirs(self.user_packages_path)
            print("Repository initialized at:", self.user_packages_path)
        else:
            print("Repository already exists at:", self.user_packages_path)

    def add_package(self, package_name, package_version, package_files):
        package_dir = os.path.join(self.user_packages_path, package_name)
        package_metadata = {
            "name": package_name,
            "version": package_version,
            "files": package_files
        }

        if not os.path.exists(package_dir):
            os.makedirs(package_dir)
        with open(os.path.join(package_dir, "metadata.json"), "w") as metadata_file:
            json.dump(package_metadata, metadata_file)
        for file in package_files:
            with open(os.path.join(package_dir, file), "w") as f:
                pass
        print("Package", package_name, "added successfully.")

    def remove_package(self, package_name):
        package_dir = os.path.join(self.user_packages_path, package_name)
        if os.path.exists(package_dir):
            shutil.rmtree(package_dir)
            print("Package", package_name, "removed successfully.")
        else:
            print("Package", package_name, "not found.")

    def list_packages(self):
        packages = os.listdir(self.user_packages_path)
        print("Available packages:")
        for package in packages:
            print("-", package)

    def install_package(self, package_name):
        package_url = self.package_urls.get(package_name)
        if package_url:
            print("Downloading package:", package_name)
            package_file_path = os.path.join(self.user_packages_path, package_name + ".zip")
            urllib.request.urlretrieve(package_url, package_file_path)
            with zipfile.ZipFile(package_file_path, 'r') as zip_ref:
                zip_ref.extractall(self.user_packages_path)
            os.remove(package_file_path)
            print("Package", package_name, "downloaded and installed successfully.")
        else:
            print("Package", package_name, "not found in the repository.")

    def update_package(self, package_name=None):
        if package_name:
            self.install_package(PackageManager,package_name)
        else:
            packages = os.listdir(self.user_packages_path)
            for package in packages:
                self.install_package(PackageManager,package)

    def prompt_download_dependencies(self, dependencies):
        print("This package has the following dependencies:")
        for dependency in dependencies:
            print("-", dependency)
        response = input("Do you want to download these dependencies? (yes/no): ").lower()
        if response == "yes":
            for dependency in dependencies:
                self.install_package(PackageManager,dependency)
        else:
            print("Dependencies not downloaded.")

    def get_package_index_url(self, package_name):
        package_url = self.package_urls.get(package_name)
        if package_url:
            return package_url
        else:
            print("Failed to determine package index URL for package", package_name)
            return None
        
    def delete_prefix(self, directory_path):
        if not os.path.exists(directory_path):
            return
        
        directories = os.listdir(directory_path)
        
        for dir_name in directories:
            if dir_name.startswith("Pryzma-packages-"):
                full_path = os.path.join(directory_path, dir_name)
                new_name = dir_name[16:]
                new_full_path = os.path.join(directory_path, new_name)
                
                if os.path.isdir(full_path):
                    if os.path.exists(new_full_path):
                        shutil.rmtree(new_full_path)
                    
                    os.rename(full_path, new_full_path)

    def get_package_version(self, package_name):
        package_dir = os.path.join(self.user_packages_path, package_name)
        metadata_path = os.path.join(package_dir, "metadata.json")
        
        if os.path.exists(metadata_path):
            with open(metadata_path, "r") as metadata_file:
                metadata = json.load(metadata_file)
                return metadata.get("version", "Version not specified.")
        else:
            return "Package not found."

    def display_help(self):
        help_text = """
        Available commands:
        - init: Initialize the package repository.
        - add <package_name> <package_version> <file1> <file2> ...: Add a new package with specified files.
        - remove <package_name>: Remove a package from the repository.
        - list: List all installed packages.
        - install <package_name>: Install a package from the repository.
        - update <package_name>: Update a specific package or all packages if no name is provided.
        - version: Display the version of all installed Pryzma packages.
        - version <package_name>: Display the version of a specific package.
        - help: Show this help message.
        - exit: Exit the Pryzma package manager.
        """
        print(help_text)

    def shell_mode(self):
        print("Entering shell mode. Type 'exit' to quit.")
        while True:
            user_input = input("> ").split()
            if user_input[0] == "exit":
                break
            elif user_input[0] == "help":
                self.display_help(PackageManager)
            elif user_input[0] == "init":
                self.initialize_repository(PackageManager)
            elif user_input[0] == "add":
                if len(user_input) < 4:
                    print("Error: You need to specify package version and files.")
                else:
                    self.add_package(PackageManager,user_input[1], user_input[2], user_input[3:])
            elif user_input[0] == "remove":
                self.remove_package(PackageManager,user_input[1])
                self.delete_prefix(PackageManager,self.user_packages_path)
            elif user_input[0] == "list":
                self.list_packages(PackageManager)
            elif user_input[0] == "install":
                self.install_package(PackageManager,user_input[1])
                self.delete_prefix(PackageManager,self.user_packages_path)
            elif user_input[0] == "update":
                if len(user_input) > 1:
                    self.update_package(PackageManager,user_input[1])
                else:
                    self.update_package(PackageManager)
                self.delete_prefix(PackageManager,self.user_packages_path)
            elif user_input[0] == "version":
                if len(user_input) > 1:
                    print(self.get_package_version(PackageManager,user_input[1]))
                else:
                    for package_name in os.listdir(self.user_packages_path):
                        print(package_name,self.get_package_version(PackageManager,package_name))
            else:
                print("Unknown command. Type 'exit' to quit.")

















if __name__ == "__main__":
    interpreter = PryzmaInterpreter()

    cls_state = True
    tkinter_enabled = False
    DEBUG_MODE = False
    history = []
    running_from_file = False

    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        arguments = sys.argv[1:]
        for arg in arguments:
            if arg.startswith("-"):
                if arg == "-d":
                    DEBUG_MODE = True
                    interpreter.debug_interpreter(file_path)
                    DEBUG_MODE = False
                    if cls_state == True:
                        interpreter.variables.clear()
                        interpreter.functions.clear()
        interpreter.interpret_file(file_path, *arguments)
        sys.exit()

    print("""Pryzma 5.2
To show the license type "license" or "help" to get help.
    """)

    while True:
        code = input("/// ")
        history.append(code)
        if code == "exit":
            break
        if code == "help":
            interpreter.print_help()
        elif code == "cls":
            interpreter.variables.clear()
        elif code == "clst":
            interpreter.variables.clear()
            cls_state = True
        elif code == "clsf":
            cls_state = False
        elif code == "clear":
            os.system('cls')
        elif code == "file":
            running_from_file = True
            interpreter.interpret_file2()
            if cls_state == True:
                interpreter.variables.clear()
                interpreter.functions.clear()
            running_from_file = False
        elif code == "license":
            interpreter.show_license()
        elif code == "debug":
            DEBUG_MODE = True
            file_path = input("Path to the file to debug ('exit' to exit the debug mode): ")
            if file_path != "exit":
                interpreter.debug_interpreter(file_path)
                DEBUG_MODE = False
                if cls_state == True:
                    interpreter.variables.clear()
                    interpreter.functions.clear()
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
                    interpreter.interpret(history[command_index])
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
        elif code.startswith("cmd"):
            if code == "cmd":
                while True:
                    command = input("Command ('exit' to exit): ")
                    if command == "exit":
                        break
                    os.system(command)
            else:
                code = code[len("cmd"):].strip()
                if code:
                    os.system(code)
                else:
                    print("No command specified.")
        elif code == "ppm":
            if not os.path.exists(PackageManager.user_packages_path):
                os.makedirs(PackageManager.user_packages_path)
            PackageManager.shell_mode(PackageManager)
        else:
            interpreter.interpret(code)
            print("variables:", interpreter.variables, "\n")
            print("functions:", interpreter.functions, "\n")
