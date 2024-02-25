import os
import re
import subprocess
import sys

class PryzmaInterpreterConverter:
    def __init__(self):
        pass

    def convert_file(self, file_path):
        dest_folder = os.path.dirname(os.path.abspath(file_path))
        with open(file_path, 'r') as file:
            program = file.read()
            python_code = self.convert(program)
            file_name = os.path.basename(file_path)
            python_file_path = os.path.join(dest_folder, os.path.splitext(file_name)[0] + '.py')
            with open(python_file_path, 'w') as python_file:
                python_file.write(python_code)
            return python_file_path

    def convert(self, program):
        lines = program.split('\n')
        python_code = []

        for line in lines:
            line = line.strip()

            if line.startswith("PRINT"):
                value = line[len("PRINT"):].strip()
                python_code.append(f'print({self.convert_expression(value)})')
            elif line.startswith("CPRINT"):
                value = line[len("CPRINT"):].strip()
                python_code.append(f'print({self.convert_expression(value)})')
            elif line.startswith("INPUT"):
                variable = line[len("INPUT"):].strip()
                python_code.append(self.convert_input(variable))
            elif "=" in line:
                variable, expression = line.split('=')
                variable = variable.strip()
                expression = expression.strip()
                python_code.append(f'{variable} = {self.convert_expression(expression)}')
            elif line.startswith("IF"):
                _, condition_actions = line.split("(")
                condition_actions = condition_actions.rstrip(")").split(",")
                if len(condition_actions) != 3:
                    print("Invalid IF instruction. Expected format: IF(condition, value, action)")
                    continue
                condition = condition_actions[0].strip()
                value = condition_actions[1].strip()
                action = condition_actions[2].strip()
                python_code.append(f'if str({self.convert_expression(condition)}) == str({self.convert_expression(value)}):')
                python_code.append('    ' + self.convert(action))
            elif line.startswith("@"):
                function_call = line[1:].strip()
                python_code.append(self.convert_function_call(function_call))
            elif line.startswith("/"):
                function_definition = line[1:].split("{")
                if len(function_definition) == 2:
                    function_name = function_definition[0].strip()
                    function_body = function_definition[1].strip().rstrip("}")
                    function_body2 = function_body.split("|")
                    python_code.append(f'def {function_name}():')
                    for body_line in function_body2:
                        python_code.append('    ' + self.convert(body_line.strip()))
                else:
                    print(f"Invalid function definition: {line}")
            elif line == "EXIT":
                python_code.append('import sys\nsys.exit()')
            elif line == "STOP":
                python_code.append('input("press Enter to exit...")')
            else:
                if line == "" or line.startswith("#"):
                    continue
                else:
                    print(f"Invalid statement: {line}")

        return '\n'.join(python_code)

    def convert_expression(self, expression):
        if re.match(r'^".*"$', expression):
            return expression
        elif expression.startswith("INT(") and expression.endswith(")"):
            return f'int({expression[4:-1]})'
        elif expression.startswith("STR(") and expression.endswith(")"):
            return f'str({expression[4:-1]})'
        elif expression.startswith("TYPE(") and expression.endswith(")"):
            return f'type({expression[5:-1]})'
        else:
            return expression

    def convert_input(self, variable):
        if "::" in variable:
            variable_name, prompt = variable.split("::", 1)
            variable_name = variable_name.strip()
            prompt = prompt.strip('"')
        else:
            variable_name = variable.strip()
            prompt = ""

        return f'{variable_name} = input("{prompt}")'

    def convert_function_call(self, function_call):
        return f'{function_call}()'

def convert_to_exe(python_file_path):
    subprocess.run(['pyinstaller', '--onefile', python_file_path])

if __name__ == "__main__":
    converter = PryzmaInterpreterConverter()

    source_file_path = input("Enter the path of the Pryzma file: ")
    source_file_dir = os.path.dirname(os.path.abspath(source_file_path))

    python_file_path = converter.convert_file(source_file_path)
    convert_to_exe(python_file_path)
    print("Conversion to EXE complete!")

    # Keep the program running until the user exits manually
    input("Press Enter to exit...")
