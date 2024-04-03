import re
import sys
import os

class PryzmaInterpreter:
    
    def __init__(self):
        self.variables = {}
        self.functions = {}

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
                elif line.startswith("cprint"):
                    value = line[len("cprint"):].strip()
                    self.cprint_value(value)
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
                elif line.startswith("ifn"):
                    condition_actions = line[len("ifn"):].split(",")
                    if len(condition_actions) != 3:
                        print("Invalid ifn instruction. Expected format: ifn condition, value, action")
                        continue
                    condition = condition_actions[0].strip()
                    value = condition_actions[1].strip()
                    action = condition_actions[2].strip()
                    if str(self.variables[value]) != str(self.variables[condition]):
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
                elif "++" in line:
                    variable = line.replace("++", "").strip()
                    self.increment_variable(variable)
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
                file.write(content)
        except Exception as e:
            print(f"Error writing to file '{file_path}': {e}")

    def assign_variable(self, variable, expression):
        self.variables[variable] = self.evaluate_expression(expression)

    def evaluate_expression(self, expression):
        if re.match(r"^\d+$", expression):
            return int(expression)
        elif re.match(r'^".*"$', expression):
            return expression[1:-1]
        elif expression in self.variables:
            return self.variables[expression]
        elif "+" in expression:
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
            return expression.split()
        elif expression.startswith("splitlines(") and expression.endswith(")"):
            return self.variables[expression[11:-1]].splitlines()
        elif expression.startswith("read(") and expression.endswith(")"):
            file_path = expression[5:-1]
            if file_path.startswith('"') and file_path.endswith('"'):
                file_path = file_path[1:-1]
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
            
    def cprint_value(self, value):
        evaluated_value = self.evaluate_expression(value)

        if evaluated_value is not None:
            if isinstance(evaluated_value, str) and '\\n' in evaluated_value:
                print(evaluated_value.replace('\\n', '\n'))
            elif re.match(r"^\d+$", str(evaluated_value)):
                print(evaluated_value)
            else:
                print(self.evaluate_expression(evaluated_value))

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
            # Get the directory of the current Pryzma file
            current_directory = os.path.dirname(self.file_path)
            # Construct the absolute path of the file to import
            absolute_file_path = os.path.join(current_directory, file_path[2:])
            with open(absolute_file_path, 'r') as file:
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
        else:
            # The file path does not start with "./", so treat it as a regular file path
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
                    index = index
                else:
                    index = self.variables[index]
                self.variables[list_name].pop(index)
            except IndexError:
                print(f"Index {index} out of range for list '{list_name}'.")
                return
        else:
            print(f"List '{list_name}' does not exist.")
    
    def print_help(self):
        print("""
commands:
        file - run a program from a file
        cls - clear the functions and variables dictionaries
        clst - set clearing functions and variables dictionaries after program execution to true
        clsf - set clearing functions and variables dictionaries after program execution to false
        exit - exit the interpreter
        help - show this help
        license - show the license
""")

if __name__ == "__main__":
    interpreter = PryzmaInterpreter()

    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        arguments = sys.argv[2:]
        print(arguments)
        interpreter.interpret_file(file_path, *arguments)
        sys.exit()

    print("""Pryzma 4.7
To show the license type "license" or "help" to get help.
    """)

    cls_state = True

    while True:
        code = input("/// ")
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
        elif code == "file":
            interpreter.interpret_file2()
            interpreter.functions.clear()
            if cls_state == True:
                interpreter.variables.clear()
        elif code == "license":
            interpreter.show_license()
        else:
            interpreter.interpret(code)
            print("variables:", interpreter.variables, "\n")
            print("functions:", interpreter.functions, "\n")
