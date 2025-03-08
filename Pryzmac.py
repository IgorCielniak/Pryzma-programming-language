import sys
import re

class Pryzmac:
    def __init__(self):
        self.variables = set()
        self.indent_level = 0

    def convert(self, pryzma_code):
        c_code = []
        lines = pryzma_code.split("\n")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("int "):
                c_code.append(self.convert_int_declaration(line))
            elif line.startswith("str "):
                c_code.append(self.convert_str_declaration(line))
            elif line.startswith("print "):
                c_code.append(self.convert_print(line))
            elif line.startswith("if "):
                c_code.append(self.convert_if(line))
            elif line.startswith("for("):
                c_code.append(self.convert_for(line))
            elif line.startswith("while "):
                c_code.append(self.convert_while(line))
            elif line.startswith("/"):
                line = line.replace("/","void ")
                if line.endswith("){"):
                    c_code.append(line)
                else:
                    if line.endswith("{"):
                        c_code.append(line[:-1]+"(){")
                    else:
                        c_code.append(line+"()")
            elif line.startswith("@"):
                c_code.append(line[1:]+";")
            elif "=" in line:
                c_code.append(self.convert_assignment(line))
            elif line == "}":
                self.indent_level -= 1
                c_code.append(" " * (self.indent_level * 4) + "}")
            else:
                print(f"Unsupported statement: {line}")

        return "\n".join(c_code)

    def convert_int_declaration(self, line):
        var_name = line.split()[1].split("=")[0].strip()
        self.variables.add(var_name)
        return line + ";"

    def convert_str_declaration(self, line):
        var_name = line.split()[1].split("=")[0].strip()
        value = line.split("=")[1].strip().strip('"')
        self.variables.add(var_name)
        return f'char {var_name}[] = "{value}";'

    def convert_print(self, line):
        value = line[len("print "):].strip()
        if value in self.variables:
            return f'printf("%d",{value});'
        else:
            return f'printf({value});'

    def convert_if(self, line):
        condition = line[3:].split("{")[0].strip()
        body = line.split("{")[1].split("}")[0].strip()
        c_body = self.convert(body)
        self.indent_level += 1
        return f"if {condition} {{\n{c_body}\n" + " " * ((self.indent_level - 1) * 4)

    def convert_for(self, line):
        parts = line[len("for("):].split(")",1)[0].split(",")
        var_name = parts[0].strip()
        self.variables.add(var_name)
        range_expr = parts[1].strip().split(":")
        start = range_expr[0].strip()
        end = range_expr[1].strip().strip("{")
        body = line.split("{")[1].split("}")[0].strip()
        c_body = self.convert(body)
        self.indent_level += 1
        return f"for (int {var_name} = {start}; {var_name} < {end}; {var_name}++) {{\n{c_body}\n" + " " * ((self.indent_level - 1) * 4)

    def convert_while(self, line):
        condition = line[len("while "):].split("{")[0].strip()
        body = line.split("{")[1].split("}")[0].strip()
        c_body = self.convert(body)
        self.indent_level += 1
        return f"while {condition} {{\n{c_body}\n" + " " * ((self.indent_level - 1) * 4)

    def convert_assignment(self, line):
        var_name = line.split("=")[0].strip()
        value = line.split("=")[1].strip()
        if var_name not in self.variables:
            self.variables.add(var_name)
            return f"int {var_name} = {value};"
        return f"{var_name} = {value};"


def main():
    pryzma_script = open(sys.argv[1]).read()

    converter = Pryzmac()
    c_code = converter.convert(pryzma_script)

    f = open("out.c", "w")
    f.write("#include <stdio.h>\n")
    f.write("int main(){" + c_code + "};")
    f.close()


if __name__ == "__main__":
    main()
