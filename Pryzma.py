import re
import sys

class PryzmaInterpreter:
    def __init__(self):
        self.variables = {}
        self.functions = {}

    def interpret_file(self, file_path):
        file_path = file_path.strip('"')
        with open(file_path, 'r') as file:
            program = file.read()
            self.interpret(program)

    def define_function(self, name, body):
        self.functions[name] = body

    def interpret(self, program):
        lines = program.split('\n')
        
        for line in lines:
            line = line.strip()

            if line.startswith("PRINT"):
                value = line[len("PRINT"):].strip()
                self.print_value(value)
            elif line.startswith("CPRINT"):
                value = line[len("CPRINT"):].strip()
                self.cprint_value(value)
            elif line.startswith("INPUT"):
                variable = line[len("INPUT"):].strip()
                self.custom_input(variable)
            elif line.startswith("FOR"):
                loop_statement = line[len("FOR"):].strip()
                loop_var, range_expr, action = loop_statement.split(",", 2)
                loop_var = loop_var.strip()
                range_expr = range_expr.strip()
                action = action.strip()
                self.for_loop(loop_var, range_expr, action)
            elif "=" in line:
                variable, expression = line.split('=')
                variable = variable.strip()
                expression = expression.strip()
                self.assign_variable(variable, expression)
            elif line.startswith("IF"):
                _, condition_actions = line.split("(")
                condition_actions = condition_actions.rstrip(")").split(",")
                if len(condition_actions) != 3:
                    print("Invalid IF instruction. Expected format: IF(condition, value, action)")
                    continue
                condition = condition_actions[0].strip()
                value = condition_actions[1].strip()
                action = condition_actions[2].strip()
                if str(self.variables[value]) == str(self.variables[condition]):
                    self.interpret(action)
            elif line.startswith("@"):
                function_name = line[1:].strip()
                if function_name in self.functions:
                    command = 0
                    while command < len(self.functions[function_name]):
                        self.interpret(self.functions[function_name][command])
                        command += 1
                else:
                    print(f"Function '{function_name}' is not defined.")
            elif line.startswith("/"):
                function_definition = line[1:].split("{")
                if len(function_definition) == 2:
                    function_name = function_definition[0].strip()
                    function_body = function_definition[1].strip().rstrip("}")
                    function_body2 = function_body.split("|")
                    self.define_function(function_name, function_body2)
                else:
                    print(f"Invalid function definition: {line}")
            elif line == "STOP":
                self.stop_program()
            else:
                if line == "" or line.startswith("#"):
                    continue
                else:
                    print(f"Invalid statement: {line}")

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
            if all(isinstance(part, str) for part in evaluated_parts):
                return "".join(evaluated_parts)
        elif "=" in expression:
            var, val = expression.split("=")
            var = var.strip()
            val = val.strip()
            if var.startswith("INT(") and var.endswith(")"):
                return int(self.evaluate_expression(val))
            elif var.startswith("STR(") and var.endswith(")"):
                return str(self.evaluate_expression(val))
            else:
                return self.evaluate_expression(val)
        elif expression.startswith("INT(") and expression.endswith(")"):
            return int(expression[4:-1])
        elif expression.startswith("STR(") and expression.endswith(")"):
            return str(expression[4:-1])
        elif expression.startswith("TYPE(") and expression.endswith(")"):
            return str(type(self.variables[expression[5:-1]]))
        else:
            try:
                return eval(expression, {}, self.variables)
            except NameError:
                print(f"Unknown variable or expression: {expression}")
        return None

    def print_value(self, value):
        evaluated_value = self.evaluate_expression(value)
        if evaluated_value is not None:
            print(evaluated_value)
            
    def cprint_value(self, value):
        evaluated_value = self.evaluate_expression(value)

        if evaluated_value is not None:
            if re.match(r"^\d+$", str(evaluated_value)):
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

    def get_input(self, prompt):
        if sys.stdin.isatty():
            return input(prompt)
        else:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            return sys.stdin.readline().rstrip('\n')

    def stop_program(self):
        input("Press Enter to exit...")

    def evaluate_condition(self, condition):
        if condition in self.variables:
            return bool(self.variables[condition])
        else:
            print(f"Unknown variable in condition: {condition}")
            return False

    def interpret_file2(self):
        file_path = input("Enter the file path of the program: ")
        self.interpret_file(file_path)

    def show_license(self):
        license_text = """
Pryzma
Copyright 2024 Igor Cielnaik

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


if __name__ == "__main__":
    interpreter = PryzmaInterpreter()

    if len(sys.argv) == 2:
        file_path = sys.argv[1]
        interpreter.interpret_file(file_path)

    print("""Pryzma 3.8
To show the license type "license" or to run code from file type "file"
    """)

    while True:
        code = input("/// ")
        if code == "exit":
            break
        elif code == "file":
            interpreter.interpret_file2()
            interpreter.functions.clear()
            interpreter.variables.clear()
        elif code == "license":
            interpreter.show_license()
        else:
            interpreter.interpret(code)
            print("variables:", interpreter.variables, "\n")
            print("functions:", interpreter.functions, "\n")
