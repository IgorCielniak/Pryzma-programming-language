import re
import sys
import os
import importlib
import importlib.util
import time
import datetime
import json
import shutil
import zipfile
import platform
import random
import ctypes
import ctypes.util
from collections import UserDict
import lzma
import struct
import mmap

class Reference:
    def __init__(self, var_name, addr=None):
        self.var_name = var_name
        self.addr = addr

class FuncReference:
    def __init__(self, func_name):
        self.func_name = func_name

class ExternFunction:
    def __init__(self, func):
        self.func = func

    def invoke(self, args):
        prepared = []
        for arg in args:
            prepared.append(self._prepare_arg(arg))
        return self.func(*prepared)

    def _prepare_arg(self, arg):
        if isinstance(arg, str):
            return arg.encode('utf-8')
        if isinstance(arg, bool):
            return int(arg)
        if isinstance(arg, bytearray):
            return bytes(arg)
        if isinstance(arg, memoryview):
            return arg.tobytes()
        if isinstance(arg, (list, tuple)):
            return self._convert_sequence(list(arg))
        return arg

    def _convert_sequence(self, sequence):
        if not sequence:
            return sequence

        if all(isinstance(item, bool) for item in sequence):
            return [int(item) for item in sequence]

        if all(isinstance(item, int) for item in sequence):
            array_type = ctypes.c_longlong * len(sequence)
            return array_type(*sequence)

        if all(isinstance(item, float) for item in sequence):
            array_type = ctypes.c_double * len(sequence)
            return array_type(*sequence)

        if all(isinstance(item, (bytes, bytearray, str, memoryview)) for item in sequence):
            converted = []
            for item in sequence:
                if isinstance(item, str):
                    converted.append(item.encode('utf-8'))
                elif isinstance(item, bytearray):
                    converted.append(bytes(item))
                elif isinstance(item, memoryview):
                    converted.append(item.tobytes())
                else:
                    converted.append(item)
            array_type = ctypes.c_char_p * len(converted)
            return array_type(*converted)

        return [self._prepare_arg(item) for item in sequence]

class PyExternFunction:
    def __init__(self, func):
        self.func = func

    def invoke(self, args):
        return self.func(*args)

class ManualMemoryManager:
    INT64_MIN = -(1 << 63)
    INT64_MAX = (1 << 63) - 1

    def __init__(self):
        self.libc = self._load_libc()
        self._malloc_fn = self.libc.malloc
        self._malloc_fn.argtypes = [ctypes.c_size_t]
        self._malloc_fn.restype = ctypes.c_void_p
        self._free_fn = self.libc.free
        self._free_fn.argtypes = [ctypes.c_void_p]
        self._free_fn.restype = None
        self.slots = {}

    def _load_libc(self):
        if os.name == "nt":
            for candidate in ("msvcrt.dll", "ucrtbase.dll"):
                try:
                    return ctypes.CDLL(candidate)
                except OSError:
                    continue
            raise RuntimeError("Unable to load the Windows C runtime for raw manual memory mode")

        libc_name = ctypes.util.find_library("c")
        candidates = [libc_name] if libc_name else []
        candidates.append(None)
        for candidate in candidates:
            try:
                return ctypes.CDLL(candidate) if candidate else ctypes.CDLL(None)
            except OSError:
                continue
        raise RuntimeError("Unable to locate libc for raw manual memory mode")

    def supports_value(self, value):
        try:
            self._value_descriptor(value)
            return True
        except (TypeError, OverflowError, ValueError):
            return False

    def allocate(self, value):
        desc = self._value_descriptor(value)
        addr = self._malloc(desc["capacity"])
        try:
            self._initialize_slot(addr, desc)
        except Exception:
            self._free(addr)
            raise
        self.slots[addr] = {
            "type": desc["type"],
            "capacity": desc["capacity"],
            "length": desc["length"],
            "ctype": desc.get("ctype")
        }
        return addr

    def read(self, addr):
        addr = int(addr)
        slot = self.slots.get(addr)
        if not slot:
            raise KeyError(f"Manual memory slot {addr} not found")
        slot_type = slot["type"]
        if slot_type == "int":
            return ctypes.c_longlong.from_address(addr).value
        if slot_type == "float":
            return ctypes.c_double.from_address(addr).value
        if slot_type == "bool":
            return bool(ctypes.c_uint8.from_address(addr).value)
        if slot_type == "bytes":
            length = slot["length"]
            if length == 0:
                return b""
            return ctypes.string_at(addr, length)
        raise TypeError(f"Unsupported slot type '{slot_type}'")

    def write(self, addr, value):
        addr = int(addr)
        slot = self.slots.get(addr)
        if not slot:
            raise KeyError(f"Manual memory slot {addr} not found")
        desc = self._value_descriptor(value)
        if desc["type"] != slot["type"]:
            raise TypeError(f"Slot at {addr} stores '{slot['type']}' but received '{desc['type']}'")

        if desc["type"] == "bytes":
            if desc["length"] > slot["capacity"]:
                raise ValueError(f"Value of length {desc['length']} exceeds slot capacity {slot['capacity']}")
            if desc["length"]:
                ctypes.memmove(addr, desc["value"], desc["length"])
            if slot["capacity"] > desc["length"]:
                ctypes.memset(addr + desc["length"], 0, slot["capacity"] - desc["length"])
            slot["length"] = desc["length"]
            return

        if desc["type"] == "int":
            ctypes.c_longlong.from_address(addr).value = desc["value"]
        elif desc["type"] == "float":
            ctypes.c_double.from_address(addr).value = desc["value"]
        elif desc["type"] == "bool":
            ctypes.c_uint8.from_address(addr).value = desc["value"]
        else:
            raise TypeError(f"Unsupported slot type '{desc['type']}'")

    def free(self, addr):
        addr = int(addr)
        if addr in self.slots:
            self._free(addr)
            self.slots.pop(addr, None)

    def reset(self):
        for addr in list(self.slots.keys()):
            self._free(addr)
        self.slots.clear()

    def _malloc(self, size):
        size = max(1, int(size))
        addr = self._malloc_fn(ctypes.c_size_t(size))
        if not addr:
            raise MemoryError("Raw manual memory allocation failed")
        return ctypes.c_void_p(addr).value

    def _free(self, addr):
        self._free_fn(ctypes.c_void_p(addr))

    def _value_descriptor(self, value):
        if isinstance(value, bool):
            return {
                "type": "bool",
                "ctype": ctypes.c_uint8,
                "capacity": 1,
                "length": 1,
                "value": 1 if value else 0
            }
        if isinstance(value, int) and not isinstance(value, bool):
            ivalue = int(value)
            if ivalue < self.INT64_MIN or ivalue > self.INT64_MAX:
                raise OverflowError("Raw manual memory only supports signed 64-bit integers")
            return {
                "type": "int",
                "ctype": ctypes.c_longlong,
                "capacity": ctypes.sizeof(ctypes.c_longlong),
                "length": ctypes.sizeof(ctypes.c_longlong),
                "value": ivalue
            }
        if isinstance(value, float):
            return {
                "type": "float",
                "ctype": ctypes.c_double,
                "capacity": ctypes.sizeof(ctypes.c_double),
                "length": ctypes.sizeof(ctypes.c_double),
                "value": float(value)
            }
        if isinstance(value, (bytes, bytearray, memoryview)):
            data = bytes(value)
            return {
                "type": "bytes",
                "ctype": None,
                "capacity": max(len(data), 1),
                "length": len(data),
                "value": data
            }
        raise TypeError(f"Raw manual memory cannot store values of type {type(value).__name__}")

    def _initialize_slot(self, addr, desc):
        slot_type = desc["type"]
        if slot_type == "int":
            ctypes.c_longlong.from_address(addr).value = desc["value"]
        elif slot_type == "float":
            ctypes.c_double.from_address(addr).value = desc["value"]
        elif slot_type == "bool":
            ctypes.c_uint8.from_address(addr).value = desc["value"]
        elif slot_type == "bytes":
            length = desc["length"]
            if length:
                ctypes.memmove(addr, desc["value"], length)
            if desc["capacity"] > length:
                ctypes.memset(addr + length, 0, desc["capacity"] - length)
        else:
            raise TypeError(f"Unsupported slot type '{slot_type}'")

class MemoryPointer:
    def __init__(self, manager, addr):
        self.manager = manager
        self.addr = addr

    def __call__(self):
        return self.manager.read(self.addr)

    def set(self, value):
        self.manager.write(self.addr, value)

    def __repr__(self):
        addr_val = int(self.addr) if self.addr else 0
        return f"<MemoryPointer addr={addr_val}>"

class eval_dict(UserDict):
    def __getitem__(self, key):
        value = super().__getitem__(key)
        return value() if callable(value) else value

class MemoryDict(eval_dict):
    def __init__(self, interpreter):
        super().__init__({})
        self.interpreter = interpreter

    def __setitem__(self, key, value):
        existing = self.data.get(key)
        if isinstance(existing, MemoryPointer):
            manager = self.interpreter.manual_memory_manager
            if manager and not manager.supports_value(value):
                raise TypeError(f"Manual memory backend cannot store value of type {type(value).__name__} for variable '{key}'")
            existing.set(value)
            return

        if self.interpreter.should_manage_value(key, value):
            addr = self.interpreter.manual_memory_manager.allocate(value)
            super().__setitem__(key, MemoryPointer(self.interpreter.manual_memory_manager, addr))
        else:
            super().__setitem__(key, value)

    def get(self, key, default=None):
        if key in self.data:
            return self[key]
        return default

    def pop(self, key, default=None):
        if key in self.data:
            value = self[key]
            del self.data[key]
            return value
        if default is None:
            raise KeyError(key)
        return default

    def items(self):
        for key in list(self.data.keys()):
            yield key, self[key]

    def values(self):
        for key in list(self.data.keys()):
            yield self[key]

    def get_raw(self, key):
        return self.data.get(key)

class PryzmaInterpreter:
    
    def __init__(self):
        self.manual_memory_manager = None
        self.manual_memory_enabled = False
        self.variables = MemoryDict(self)
        self.functions = {}
        self.structs = {}
        self.locals = {}
        self.custom_handlers = {}
        self.deleted_keywords = []
        self.variables["interpreter_path"] = __file__
        self.variables["err"] = 0
        self.in_try_block = False
        self.in_func = [False]
        self.function_tracker = [None]
        self.function_ids = [None]
        self.current_func_name = None
        self.preprocess_only = False
        self.no_preproc = False
        self.forward_declare = False
        self.nan = False
        self.return_stops = False
        self.return_val = None
        self.break_stack = []
        self.main_file = 1
        self.mem = bytearray(4096)
        self.fail = False
        self.unpack_ = False
        self.lines_map = []
        self.lines_map_done = False
        self.defer_stack = {}
        self.escape = False
        self.in_loop = False
        self.debug = False
        self.gc = True
        self.manual_memory_protected = set()
        self.c_extern_wildcards = []
        self.asm_backend = "emu"

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
                self.pre_interpret(self.unpack(file_path))
            else:
                with open(self.file_path, 'r') as file:
                    program = file.read()
                    self.pre_interpret(program)
        except FileNotFoundError:
            print(f"File '{self.file_path}' not found.")

    def split_on_comment(self, line):
        in_string = False
        escape = False

        for i in range(len(line)):
            char = line[i]

            if escape:
                escape = False
                continue

            if char == "\\":
                escape = True
                continue

            if char in ("'", '"'):
                if not in_string:
                    in_string = char
                elif in_string == char:
                    in_string = False

            if not in_string and i + 1 < len(line) and line[i:i+2] == "//":
                return line[:i]

        return line

    def preprocess(self, program):
        program = program.splitlines()
        for line in range(0,len(program)):
            program[line] = self.split_on_comment(program[line])
            if program[line].startswith("#np") or (program[line].startswith("#preproc") and "np" in program[line]):
                self.no_preproc = True
            if self.lines_map_done == False:
                self.lines_map.append((program[line], line))
        self.lines_map_done = True
        in_str = False
        for i, line in enumerate(program):
            for char in line:
                if char == '"':
                    in_str = not in_str
            if in_str == False:
                program[i] += ";"
        program = "".join(program)

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

    def pre_interpret(self, program):
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

        for i in range(0, len(lines)):
            if lines[i].startswith("#replace"):
                a, b = lines[i][8:].split("->")
                a = str(self.evaluate_expression(a.strip()))
                b = str(self.evaluate_expression(b.strip()))
                for i, line in enumerate(lines):
                    lines[i] = re.sub(a, b, line)
            else:
                self.interpret(lines[i])

    def interpret(self, line):
        lines = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', line)
        for line in lines:
            if self.main_file < 1:
                self.no_preproc = False

            self.main_file -= 1

            if not self.in_func[-1]:
                self.current_line = 0

            for stmt, num in self.lines_map:
                if line.startswith(stmt.strip()) and stmt.strip() != "":
                    if not self.in_loop:
                        self.lines_map.remove((stmt, num))
                    self.current_line = num + 1
                    break
            line = line.strip()

            if line == "" or line.startswith("//"):
                return

            deleted_keyword = False

            for key_word in self.deleted_keywords:
                if key_word in line and not (line.startswith("disablekeyword(") or line.startswith("enablekeyword(")):
                    keyword = key_word
                    deleted_keyword = True

            if deleted_keyword:
                self.error(1, f"Error at line {self.current_line}: keyword deleted '{keyword}'")
                return

            handled = False
            for handler in self.custom_handlers.values():
                if handler(self, line):
                    handled = True
                    break

            if handled:
                return

            if self.gc == True:
                to_remove = []
                for var in self.locals:
                    self.locals[var] = [item for item in self.locals[var] if self.ref_to_local_exists(var) or item[2] in self.function_ids]
                    if not self.locals[var]:
                        to_remove.append(var)
                for var in to_remove:
                    self.locals.pop(var)

            try:
                if line.startswith("print"):
                    value = line[5:].strip()
                    self.print_value(value)
                elif line.startswith("input"):
                    variable = line[5:].strip()
                    self.custom_input(variable)
                elif line.startswith("#"):
                    if line.startswith("#preproc"):
                        if "=" in line:
                            self.process_args(line.split("=")[1].split(","))
                    elif line.startswith("#insert"):
                        file_path = self.evaluate_expression(line[7:].strip())
                        program = None
                        with open(file_path, "rb") as f:
                            data = f.read()
                        if data.startswith("prz".encode('utf-8')):
                            program = self.decompress(data[3:])
                        if not program:
                            with open(file_path, 'r') as file:
                                program = file.read()
                        self.pre_interpret(program)
                    elif line == "#shell":
                        while True:
                            code = input("/// ")
                            if code == "exit":
                                break
                            shell(code)
                    else:
                        self.process_args(line[1:].split(","))
                elif line.startswith("{"):
                    variables, instance = line.split("=")
                    variables = variables.strip()
                    instance = instance.strip()
                    args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', variables[1:-1])
                    if instance in args:
                        self.error(39, f"Error at line {self.current_line}: overlaping names of struct instance and one of variables used for destructuring")
                        return
                    for i, key in enumerate(self.variables[instance].keys()):
                        self.variables[args[i]] = self.variables[instance][key]
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
                        self.error(41, f"Error at line {self.current_line}: List not found for the foreach function.")

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
                    self.in_loop = True
                    self.for_loop(loop_var, range_expr, actions)
                    self.in_loop = False
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
                    if "elif" in line:
                        line = list(line)
                        depth = 0
                        in_str = False
                        for i, char in enumerate(line):
                            if char == "{" and not in_str:
                                depth += 1
                            elif char == "}" and not in_str:
                                depth -= 1
                            elif char == '"':
                                in_str = not in_str
                            elif depth == 0 and char == "e" and line[i + 1] == "l" and line[i + 2] == "i" and line[i + 3] == "f":
                                line[i] = "#"
                                line[i + 1] = "$"
                                line[i + 2] = "&"
                                line[i + 3] = "@"
                        line = "".join(line)
                    branches = line.split("#$&@")
                    handeled = False
                    for branch in branches:
                        if handeled == True:
                            break
                        condition, action = branch.strip()[1:-1].split("){", 1)
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
                        if self.evaluate_expression(condition.strip()):
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
                    self.break_stack.append(False)
                    while self.evaluate_expression(condition):
                        for action in actions:
                            self.interpret(action)
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
                        self.error(2, f"Invalid function definition at line {self.current_line}")
                elif line.startswith("@"):
                    self.in_func.append(True)
                    function_name = line[1:].strip()
                    self.variables["args"] = []
                    if "(" in function_name:
                        function_name, arg = function_name.split("(", 1)
                        self.current_func_name = function_name
                        if arg.endswith(")"):
                            arg = arg[:-1]
                        if arg:
                            arg = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', arg)
                            for args in range(len(arg)):
                                arg[args] = self.evaluate_expression(arg[args].strip())
                            self.variables["args"] = arg
                    self.function_tracker.append(function_name)
                    self.function_ids.append(random.randint(0,100000000))
                    var_entry = self.variables.get_raw(function_name)
                    if isinstance(var_entry, FuncReference):
                        function_name = var_entry.func_name
                        var_entry = self.variables.get_raw(function_name)

                    if var_entry is None:
                        var_entry = self.resolve_wildcard_function(function_name)

                    if isinstance(var_entry, (ExternFunction, PyExternFunction)):
                        try:
                            result = var_entry.invoke(self.variables["args"])
                            self.ret_val = result
                        except Exception as e:
                            self.error(12, f"Error while calling extern function '{function_name}': {e}")
                        finally:
                            self.in_func.pop()
                            self.function_tracker.pop()
                            self.function_ids.pop()
                        return
                    if function_name not in self.functions:
                        self.error(38, f"Error at line {self.current_line}: Referenced function '{function_name}' no longer exists")
                        return
                    if function_name in self.functions:
                        try:
                            command = 0
                            while command < len(self.functions[function_name]):
                                inst = self.functions[function_name][command]
                                self.interpret(inst)
                                if self.return_stops and inst.strip().startswith("return"):
                                    break
                                command += 1
                        finally:
                            func_id = self.function_ids[-1]
                            if (function_name, func_id) in self.defer_stack:
                                while self.defer_stack[(function_name, func_id)]:
                                    deferred = self.defer_stack[(function_name, func_id)].pop()
                                    deferred = deferred.split("|")
                                    for line in deferred:
                                        self.interpret(line.strip())
                            if self.escape == False:
                                if self.gc == True:
                                    to_remove = []
                                    for var in self.locals:
                                        self.locals[var] = [item for item in self.locals[var] if item[2] != func_id]
                                        if not self.locals[var]:
                                            to_remove.append(var)
                                    for var in to_remove:
                                        self.locals.pop(var)
                    else:
                        self.error(3, f"Error at line {self.current_line}: Function '{function_name}' is not defined.")
                    self.in_func.pop()
                    self.function_tracker.pop()
                    self.function_ids.pop()
                elif line.startswith("pyeval(") and line.endswith(")"):
                    parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[7:-1])
                    if len(parts) == 1:
                        eval(self.evaluate_expression(parts[0]))
                    else:
                        eval(self.evaluate_expression(parts[0]), self.evaluate_expression(parts[1]))
                elif line.startswith("pyexec(") and line.endswith(")"):
                    parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[7:-1])
                    if len(parts) == 1:
                        exec(self.evaluate_expression(parts[0]))
                    else:
                        exec(self.evaluate_expression(parts[0]),self.evaluate_expression(parts[1]))
                elif line.startswith("exec(") and line.endswith(")"):
                    code = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[5:-1])
                    for part in code:
                        self.interpret(self.evaluate_expression(part))
                elif line.startswith("eval(") and line.endswith(")"):
                    code = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[5:-1])
                    for part in code:
                        self.evaluate_expression(part)
                elif line.startswith("isolate(") and line.endswith(")"):
                    args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[8:-1])
                    isolated_interpreter = None
                    for arg in args:
                        if arg.startswith("isolate"):
                            args.remove(arg)
                            isolated_interpreter = self.variables[arg.split("=", 1)[1].strip()]
                    if not isolated_interpreter:
                        isolated_interpreter = PryzmaInterpreter()
                    for part in args:
                        isolated_interpreter.interpret(self.evaluate_expression(part))
                elif line.startswith("try{") and line.endswith("}"):
                    self.in_try_block = True
                    catch_block = None
                    if "catch(" in line:
                        line, catch_block = line.split("catch(", 1)
                    rep_in_line = 0
                    char_ = 0
                    in_str = False
                    chars = list(line[4:-1])
                    for char in chars:
                        if char == "{":
                            rep_in_line += 1
                        elif char == "}":
                            rep_in_line -= 1
                        elif not in_str and char == '"':
                            in_str = True
                        elif in_str and char == '"':
                            in_str = False
                        elif (rep_in_line == 0 and char == "|" and not in_str):
                            chars[char_] = "@!#$%^"
                        char_ += 1
                    body = "".join(chars)
                    instructions = body.split("@!#$%^")
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
                elif line.startswith("loc "):
                    var, value = line[3:].split("=", 1)
                    var = var.strip()
                    value = self.evaluate_expression(value.strip())
                    if var not in self.locals:
                        self.locals[var] = []
                    self.locals[var].append((value, self.function_tracker[-1], self.function_ids[-1]))
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
                        ref = False
                        if variable.lstrip("*") in self.variables:
                            if isinstance(self.variables[variable.lstrip("*")], Reference):
                                var = self.variables[variable.lstrip("*")].var_name
                                if var in self.locals:
                                    variable = var
                                    ref = True
                        if variable.lstrip("*") in self.locals:
                            if isinstance(self.locals[variable.lstrip("*")][0], Reference):
                                variable = self.locals[variable.lstrip("*")][0].var_name
                        if variable.lstrip("*") in self.locals:
                            self.assign_value_local(variable, expression, ref)
                        else:
                            self.assign_value(variable.strip(), expression)
                elif "+=" in line:
                    line = line.split("+=")
                    if len(line) != 2:
                        self.error(4, f"Error at line {self.current_line}: Too much arguments")
                        return
                    var = line[0].strip()
                    var2 = line[1].strip()
                    self.increment_var(var, var2)
                elif "-=" in line:
                    line = line.split("-=")
                    if len(line) != 2:
                        self.error(5, f"Error at line {self.current_line}: Too much arguments")
                        return
                    var = line[0].strip()
                    var2 = line[1].strip()
                    self.decrement_var(var, var2)
                elif line.startswith("use"):
                    if "with" in line:
                        line, directive = line.split("with")
                        if directive.strip() != "":
                            nan = self.nan
                            fd = self.forward_declare
                            np = self.no_preproc
                            self.process_args(directive.strip()[1:].split(","))
                            alias = None
                            if " as " in line:
                                file_path, alias = line[3:].strip().split(" as ")
                            else:
                                file_path = line[3:].strip()
                            self.import_functions(file_path, alias)
                            self.nan = nan
                            self.forward_declare = fd
                            self.no_preproc = np
                    else:
                        file_path = line[3:].strip()
                        alias = None
                        if " as " in line:
                            file_path, alias = file_path.split(" as ")
                        self.import_functions(file_path, alias)
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
                elif line.startswith("remove") and not line.startswith("remove_path("):
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
                        self.error(6, f"Error at line {self.current_line}: Invalid number of arguments for write()")
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
                    self.increment_var(variable, "1")
                elif "--" in line:
                    variable = line.replace("--", "").strip()
                    self.decrement_var(variable, "1")
                elif line.startswith("move(") and line.endswith(")"):
                    instructions = line[5:-1].split(",")
                    if len(instructions) != 3:
                        self.error(7, f"Error at line {self.current_line}: Invalid move instruction syntax. Expected format: move(old index, new index, list name)")
                        return
                    list_name = instructions[2].strip()
                    try:
                        old_index = int(instructions[0])
                        new_index = int(instructions[1])
                        value = self.variables[list_name].pop(old_index)
                        self.variables[list_name].insert(new_index, value)
                    except ValueError:
                        self.error(8, f"Error at line {self.current_line}: Invalid index")
                elif line.startswith("swap(") and line.endswith(")"):
                    instructions = line[5:-1].split(",")
                    if len(instructions) != 3:
                        self.error(9, f"Error at line {self.current_line}: Invalid swap instruction syntax. Expected format: swap(index 1, index 2, list name)")
                        return
                    list_name = instructions[2].strip()
                    try:
                        index_1 = int(self.evaluate_expression(instructions[0].strip()))
                        index_2 = int(self.evaluate_expression(instructions[1].strip()))
                        self.variables[list_name][index_1], self.variables[list_name][index_2] = self.variables[list_name][index_2], self.variables[list_name][index_1]
                    except ValueError:
                        self.error(10, "Invalid index for swap()")
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
                    time_to_wait = float(self.evaluate_expression(line[5:-1]))
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
                elif line.startswith("defer{") and line.endswith("}"):
                    if (self.function_tracker[-1], self.function_ids[-1]) in self.defer_stack:
                        self.defer_stack[(self.function_tracker[-1], self.function_ids[-1])].append(line[6:-1])
                    else:
                        self.defer_stack[(self.function_tracker[-1], self.function_ids[-1])] = []
                        self.defer_stack[(self.function_tracker[-1], self.function_ids[-1])].append(line[6:-1])
                elif line.startswith("return"):
                    self.ret_val = self.evaluate_expression(line[6:].strip())
                elif line == "break":
                    self.break_stack[-1] = True
                elif (line.startswith("asm{") or line.startswith("asm {")) and line.endswith("}"):
                    self.execute_inline_asm(line)
                    return
                elif (line.startswith("py{") or line.startswith("py {")) and line.endswith("}"):
                    line = line[3:-1] if line.starstwith("py{") else line[4:-1]
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
                elif line.startswith("remove_path(") and line.endswith(")"):
                    path = self.evaluate_expression(line[12:-1])
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
                elif line.startswith("patch(") and line.endswith(")"):
                    f1, f2 = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[6:-1])
                    f1 = self.evaluate_expression(f1)
                    f2 = self.evaluate_expression(f2)
                    if f1 not in self.functions or f2 not in self.functions:
                        self.error(40, "Name of a non existing function pased as an argument to patch()")
                    self.functions[f1] = self.functions[f2]
                elif line.startswith("json_dump(") and line.endswith(")"):
                    args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', line[10:-1])
                    obj = self.evaluate_expression(args[0])
                    if len(args) > 1:
                        file_path = self.evaluate_expression(args[1])
                        with open(file_path, "w") as f:
                            json.dump(obj, f)
                    else:
                        print(json.dumps(obj))
                elif line.startswith("using"):
                    parts = line.split()
                    is_global = len(parts) > 2 and parts[1] == "global"
                    instance_name = parts[-1]

                    instance = self.evaluate_expression(instance_name)

                    if isinstance(instance, Reference):
                        instance = self.variables[instance.var_name]

                    if instance is None:
                        self.error(28, f"Error at line {self.current_line}: Unknown variable or expression: {instance_name}")
                        return

                    if not isinstance(instance, dict):
                        self.error(42, f"Error at line {self.current_line}: 'using' statement can only be used with structs.")
                        return

                    if is_global:
                        for key, value in instance.items():
                            self.variables[key] = value
                    elif self.in_func[-1]:
                        for key, value in instance.items():
                            if key not in self.locals:
                                self.locals[key] = []
                            self.locals[key].append((value, self.function_tracker[-1], self.function_ids[-1]))
                    else:
                        for key, value in instance.items():
                            self.variables[key] = value
                elif ".@" in line:
                    var_name, func = line.split(".@", 1)
                    func_name, args = func[:-1].split("(", 1)
                    code = f"@{func_name}({var_name}, {args})"
                    self.interpret(code)
                elif line.startswith("extern"):
                    file_name, func_name = line[6:].strip().split(" ", 1)
                    file_name = file_name.strip('"')

                    func_name = func_name.strip()

                    functions = [func_name]

                    if func_name.startswith("{") and func_name.endswith("}"):
                        functions = re.split(r'[|,]', func_name[1:-1])
                        functions = list(filter(None, functions))
                        for i, func in enumerate(functions):
                            functions[i] = functions[i].strip(",").strip()

                    c_functions = ctypes.CDLL(file_name)
                    wildcard = False
                    cleaned_functions = []
                    for func in functions:
                        if func == "*":
                            wildcard = True
                            continue
                        cleaned_functions.append(func)

                    for func in cleaned_functions:
                        try:
                            c_func = getattr(c_functions, func)
                        except AttributeError:
                            print(f"Function '{func}' not found in '{file_name}'.")
                            return
                        self.configure_c_function_defaults(func, c_func)
                        self.variables[func] = ExternFunction(c_func)

                    if wildcard:
                        self.register_c_wildcard_library(c_functions)
                elif line.startswith("pyextern"):
                    parts = line.split(None, 2)
                    if len(parts) < 3:
                        self.error(11, f"Invalid pyextern statement at line {self.current_line}: {line}")
                        return

                    module_ref = self.resolve_pyextern_module_reference(parts[1])
                    module = self.load_pyextern_module(module_ref)

                    if module is None:
                        return

                    function_specs = self.parse_pyextern_functions(parts[2])

                    if not function_specs:
                        self.error(11, f"No functions specified for pyextern at line {self.current_line}.")
                        return

                    wildcard = False

                    for func_name, alias in function_specs:
                        if func_name == "*":
                            wildcard = True
                            continue

                        py_callable = self.resolve_pyextern_callable(module, func_name)
                        if py_callable is None:
                            print(f"Function '{func_name}' not found in '{module_ref}'.")
                            continue
                        if not callable(py_callable):
                            print(f"Attribute '{func_name}' is not callable in '{module_ref}'.")
                            continue
                        self.variables[alias] = PyExternFunction(py_callable)

                    if wildcard:
                        self.bind_all_pyextern_callables(module)
                elif line == "stop":
                    sys.exit()
                else:
                    if not handled:
                        self.error(11, f"Invalid statement at line {self.current_line}: {line}")

            except Exception as e:
                self.error(12, f"Error at line {self.current_line}: {e}")

    def execute_inline_asm(self, raw_line):
        try:
            from keystone import Ks, KS_ARCH_X86, KS_MODE_64
        except ImportError:
            print("ERROR: missing keystone")
            return

        backend = (self.asm_backend or "emu").lower()
        if backend not in {"emu", "native"}:
            backend = "emu"

        segment = raw_line[4:-1] if raw_line.startswith("asm{") else raw_line[5:-1]
        code = list(filter(None, segment.split("|")))
        for idx in range(len(code)):
            code[idx] = self.evaluate_expression(code[idx].strip())

        if not code:
            print("No asm instructions found.")
            return

        context = self._build_inline_asm_context(backend)
        if context is None:
            return

        resolved_body = self._resolve_inline_asm_vars(code, context["address_lookup"])
        asm_lines = ["push r11"]
        asm_lines.extend(resolved_body)
        asm_lines.append("pop r11")
        asm_lines.append("ret")
        asm_text = "\n".join(asm_lines)

        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        try:
            machine_code, _ = ks.asm(asm_text)
        except Exception as exc:
            print("ASM ERROR:", exc)
            return

        shellcode = bytes(machine_code)
        if not shellcode:
            print("No bytes assembled.")
            return

        if backend == "native":
            if not self._run_inline_asm_native(shellcode):
                return
        else:
            if not self._run_inline_asm_emulated(shellcode, context):
                return

        context["sync_back"]()

    def _build_inline_asm_context(self, backend):
        if backend == "native":
            var_mem = {}
            for name, value in self.variables.items():
                if isinstance(value, int):
                    var_mem[name] = ctypes.c_int64(value)

            def address_lookup(var_name):
                ref = var_mem.get(var_name)
                if ref is None:
                    return None
                return ctypes.addressof(ref)

            def sync_back():
                for name, ref in var_mem.items():
                    try:
                        self.variables[name] = ref.value
                    except Exception:
                        pass

            return {
                "backend": "native",
                "var_mem": var_mem,
                "address_lookup": address_lookup,
                "sync_back": sync_back,
            }

        if backend == "emu":
            var_mem = {}
            offset = 0
            for name, value in self.variables.items():
                if isinstance(value, int):
                    var_mem[name] = {
                        "offset": offset,
                        "value": ctypes.c_int64(value).value,
                    }
                    offset += 8

            var_base = 0x40000000
            var_size = self._align_to_page(offset)

            def address_lookup(var_name):
                entry = var_mem.get(var_name)
                if entry is None:
                    return None
                return var_base + entry["offset"]

            def sync_back():
                for name, entry in var_mem.items():
                    self.variables[name] = entry.get("value", self.variables.get(name, 0))

            return {
                "backend": "emu",
                "var_mem": var_mem,
                "var_base": var_base,
                "var_size": var_size,
                "address_lookup": address_lookup,
                "sync_back": sync_back,
            }

        print(f"Unknown inline asm backend '{backend}'")
        return None

    def _resolve_inline_asm_vars(self, lines, address_lookup):
        token_re = re.compile(r"\[|\]|,|0x[0-9A-Fa-f]+|[A-Za-z_][A-Za-z0-9_]*|[-+]?\d+|\S")
        arith_ops = {"add", "sub", "imul", "and", "or", "xor"}
        register_matcher = re.compile(r"^[er]?[abcd]x$|^r[0-9a-z]+$")

        def addr_load(addr_value, dst_reg):
            return [f"mov r11, {hex(addr_value)}", f"mov {dst_reg}, qword ptr [r11]"]

        def addr_store(addr_value, src_reg):
            return [f"mov r11, {hex(addr_value)}", f"mov qword ptr [r11], {src_reg}"]

        resolved = []
        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            toks = token_re.findall(stripped)
            mnemonic = toks[0].lower() if toks else ""
            operands = [tok for tok in toks[1:] if tok != ","]

            if mnemonic == "mov" and len(operands) >= 2:
                op1, op2 = operands[0], operands[1]

                addr = address_lookup(op2)
                if addr is not None and register_matcher.match(op1):
                    resolved.extend(addr_load(addr, op1))
                    continue

                addr = address_lookup(op1)
                if addr is not None:
                    resolved.extend(addr_store(addr, op2))
                    continue

                resolved.append(stripped)
                continue

            if mnemonic in arith_ops and len(operands) >= 2:
                dst, src = operands[0], operands[1]
                addr = address_lookup(src)
                if addr is not None:
                    resolved.append(f"mov r11, {hex(addr)}")
                    resolved.append(f"{mnemonic} {dst}, qword ptr [r11]")
                    continue
                resolved.append(stripped)
                continue

            resolved.append(stripped)

        return resolved

    def _run_inline_asm_native(self, shellcode):
        size = len(shellcode)
        if size == 0:
            return False

        try:
            exec_mem = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        except Exception as exc:
            print("Inline asm allocation error:", exc)
            return False

        try:
            exec_mem.write(shellcode)
            exec_mem.seek(0)
            addr = ctypes.addressof(ctypes.c_char.from_buffer(exec_mem))
            func = ctypes.CFUNCTYPE(None)(addr)
            func()
        except Exception as exc:
            print("Runtime error while executing asm:", exc)
            exec_mem.close()
            return False

        exec_mem.close()
        return True

    def _run_inline_asm_emulated(self, shellcode, context):
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
            from unicorn.x86_const import UC_X86_REG_RSP
        except ImportError:
            print("ERROR: missing unicorn for asm emulation")
            return False

        code_addr = 0x10000000
        stack_addr = 0x20000000
        stack_size = 0x10000
        exit_addr = 0x50000000

        emu = Uc(UC_ARCH_X86, UC_MODE_64)

        code_size = self._align_to_page(len(shellcode)) or 0x1000
        emu.mem_map(code_addr, code_size)
        emu.mem_write(code_addr, shellcode)

        emu.mem_map(stack_addr, stack_size)
        stack_top = stack_addr + stack_size
        emu.reg_write(UC_X86_REG_RSP, stack_top - 8)
        emu.mem_map(exit_addr, 0x1000)
        emu.mem_write(stack_top - 8, struct.pack("<Q", exit_addr))

        var_mem = context.get("var_mem", {})
        var_base = context.get("var_base", 0x40000000)
        var_size = context.get("var_size", 0)

        if var_mem and var_size:
            emu.mem_map(var_base, var_size)
            for entry in var_mem.values():
                addr = var_base + entry["offset"]
                emu.mem_write(addr, struct.pack("<q", entry["value"]))

        try:
            emu.emu_start(code_addr, exit_addr)
        except UcError as exc:
            print("ASM EMU ERROR:", exc)
            return False

        if var_mem and var_size:
            for entry in var_mem.values():
                addr = var_base + entry["offset"]
                entry["value"] = struct.unpack("<q", emu.mem_read(addr, 8))[0]

        return True

    @staticmethod
    def _align_to_page(size):
        if size <= 0:
            return 0
        page = 0x1000
        return ((size + page - 1) // page) * page

    def error(self, code, message):
        if not self.in_try_block:
            self.in_func_err()
            self.variables["err"] = code
            print(message)
            if self.fail:
                sys.exit()
        else:
            self.variables["err"] = code

    def in_func_err(self):
        if self.in_func[-1]:
            print(f"Error while calling function '{self.function_tracker[-1]}'")

    def ref_to_local_exists(self, local):
        for var in self.variables:
            if isinstance(self.variables[var], Reference) and self.variables[var].var_name == local:
                return True
        for var in self.locals:
            if isinstance(self.locals[var][0], Reference) and self.locals[var][0].var_name == local:
                return True
        return False

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
        if "rs" in args:
            self.return_stops = True
        if "rds" in args:
            self.return_stops = False
        if "esc" in args:
            self.escape = True
        if "desc" in args:
            self.escape = False
        if "gc" in args:
            self.gc = True
        if "ngc" in args:
            self.gc = False
        if ("asm_native" in args) or ("anat" in args):
            self.asm_backend = "native"
        if ("asm_emu" in args) or ("asm_emulator" in args) or ("aemu" in args):
            self.asm_backend = "emu"
        if "mmraw" in args or "mm" in args:
            self.enable_manual_memory()
        if "amm" in args:
            self.disable_manual_memory()

    def should_manage_value(self, key, value):
        if not self.manual_memory_enabled or self.manual_memory_manager is None:
            return False
        if isinstance(value, (Reference, FuncReference, ExternFunction, PyExternFunction, MemoryPointer)):
            return False
        if callable(value):
            return False
        return self.manual_memory_manager.supports_value(value)

    def enable_manual_memory(self):
        if self.manual_memory_enabled:
            return
        if self.manual_memory_manager is None:
            try:
                self.manual_memory_manager = ManualMemoryManager()
            except RuntimeError as exc:
                print(f"Manual memory unavailable: {exc}")
                return
        self.manual_memory_enabled = True

        for key, stored in list(self.variables.data.items()):
            if isinstance(stored, MemoryPointer):
                continue
            if not self.should_manage_value(key, stored):
                continue
            addr = self.manual_memory_manager.allocate(stored)
            self.variables.data[key] = MemoryPointer(self.manual_memory_manager, addr)

    def disable_manual_memory(self):
        if not self.manual_memory_enabled or self.manual_memory_manager is None:
            return
        for key, stored in list(self.variables.data.items()):
            if isinstance(stored, MemoryPointer):
                value = stored()
                self.variables.data[key] = value
        if self.manual_memory_manager:
            self.manual_memory_manager.reset()
        self.manual_memory_manager = None
        self.manual_memory_enabled = False


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
                self.error(13, f"Module '{module_name}' does not have a 'start' function.")
        except Exception as e:
            self.error(14, f"Error loading module '{module_path}': {e}")

    def write_to_file(self, file_path, mode, content):
        try:
            with open(file_path, mode) as file:
                if isinstance(content, list):
                    for line in content:
                        file.write(f"{line}\n")
                else:
                    file.write(content)
        except Exception as e:
            self.error(15, f"Error at line {self.current_line} while writing to file '{file_path}': {e}")

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
                return eval(self.evaluate_expression(parts[0]), self.evaluate_expression(parts[1]))
        elif expression.startswith("pyexec(") and expression.endswith(")"):
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[7:-1])
            if len(parts) == 1:
                return exec(self.evaluate_expression(parts[0]))
            else:
                return exec(self.evaluate_expression(parts[0]), self.evaluate_expression(parts[1]))
        elif expression.startswith("exec(") and expression.endswith(")"):
            code = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[5:-1])
            for part in code:
                self.ret_val = None
                self.interpret(self.evaluate_expression(part))
                if self.ret_val != None:
                    return self.ret_val
        elif expression.startswith("eval(") and expression.endswith(")"):
            code = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[5:-1])
            for part in code:
                result = self.evaluate_expression(part)
                if result != None:
                    return result
        elif expression.startswith("new_isolate(") and expression.endswith(")"):
            return PryzmaInterpreter()
        elif expression.startswith("isolate(") and expression.endswith(")"):
            args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[8:-1])
            isolated_interpreter = None
            for arg in args:
                if arg.startswith("isolate"):
                    args.remove(arg)
                    isolated_interpreter = self.variables[arg.split("=", 1)[1].strip()]
            if not isolated_interpreter:
                isolated_interpreter = PryzmaInterpreter()
            for part in args:
                isolated_interpreter.ret_val = None
                isolated_interpreter.interpret(self.evaluate_expression(part))
                if isolated_interpreter.ret_val != None:
                    return isolated_interpreter.ret_val
        elif expression.startswith("replace(") and expression.endswith(")"):
            expression = expression[8:-1]
            parts = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression)
            if len(parts) != 3:
                self.error(16, f"Error at line {self.current_line}: Invalid number of arguments for replace function.")
                return None
            value = self.evaluate_expression(parts[0].strip())
            old = self.evaluate_expression(parts[1].strip())
            new = self.evaluate_expression(parts[2].strip())
            if old == "\\n":
                old = "\n"
            if new == "\\n":
               new = "\n"
            return value.replace(old, new)
        elif expression.startswith("json_dump(") and expression.endswith(")"):
            args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[10:-1])
            obj = self.evaluate_expression(args[0])
            if len(args) > 1:
                file_path = self.evaluate_expression(args[1])
                with open(file_path, "w") as f:
                    json.dump(obj, f)
            else:
                return json.dumps(obj)
        elif expression.startswith("json_load(") and expression.endswith(")"):
            arg = self.evaluate_expression(expression[10:-1])
            if os.path.exists(arg):
                with open(arg, "r") as f:
                    return json.load(f)
            else:
                return json.loads(arg)
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

            args = list(filter(None, re.split(r'\$\#\@\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', args)))
            name = name.strip()

            struct_def = self.structs[name]
            result = {}

            pairs = []

            for i, arg in enumerate(args):
                if "=" in arg:
                    args[i] = [arg.strip() for arg in arg.strip().split("=", 1)]
                    pairs.append(i)
                else:
                    args[i] = self.evaluate_expression(arg.strip()) if arg != "" else None

            for i, arg in enumerate(args):
                if i in pairs:
                    key = args[i][0].strip()
                    value = args[i][1].strip()
                    result[key] = self.evaluate_expression(value)

            for i, (key, default_value) in enumerate(struct_def.items()):
                if i < len(args) and args[i] is not None:
                    if key not in result.keys():
                        result[key] = self.evaluate_expression(args[i]) if repr(args[i]).startswith("@") else args[i]
                else:
                    if key not in result.keys():
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
                self.error(17, f"Error at line {self.current_line}: Invalid number of arguments for resplit(). Expected 2 arguments.")
                return None
    
            regex_pattern = self.evaluate_expression(parts[0].strip())
            string_to_split = self.evaluate_expression(parts[1].strip())
    
            if not isinstance(regex_pattern, str):
                self.error(18, f"Error at line {self.current_line}: The first argument of resplit() must be a string (regex pattern).")
                return None
            regex_pattern = r"{}".format(regex_pattern) 
            if not isinstance(string_to_split, str):
                self.error(19, f"Error at line {self.current_line}: The second argument of resplit() must be a string.")
                return None
    
            try:
                return re.split(regex_pattern, string_to_split)
            except re.error as e:
                self.error(20, f"Error at line {self.current_line}: Invalid regex pattern: {e}")
                return None
        elif expression.startswith("in(") and expression.endswith(")"):
            value1, value2 = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[3:-1])
            value1 = self.evaluate_expression(value1.strip())
            value2 = self.evaluate_expression(value2.strip())
            try:
                return value2 in value1
            except Exception as e:
                self.error(21, f"in() function error at line {self.current_line}: {e}")
        elif expression.startswith("splitby(") and expression.endswith(")"):
            args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[8:-1])
            if len(args) < 2:
                self.error(22, f"Error at line {self.current_line}: Invalid number of arguments for splitby function.")
                return None
            char_to_split = self.evaluate_expression(args[0].strip())
            string_to_split = self.evaluate_expression(args[1].strip())
            if len(args) == 3:
                return string_to_split.split(char_to_split, self.evaluate_expression(args[2].strip()))
            else:
                return string_to_split.split(char_to_split)
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
                self.error(23, f"Error at line {self.current_line}: File '{file_path}' not found.")
                return ""
        elif expression.startswith("index(") and expression.endswith(")"):
            args = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[6:-1])
            if len(args) != 2:
                self.error(24, f"Error at line {self.current_line}: Invalid number of arguments for index function.")
                return None
            list_name = args[0].strip()
            value = args[1].strip()
            if list_name in self.variables and isinstance(self.variables[list_name], list):
                value = self.evaluate_expression(value.strip())
                try:
                    index_value = self.variables[list_name].index(value)
                    return index_value
                except ValueError:
                    self.error(25, f"Error at line {self.current_line}: Value '{value}' not found in list '{list_name}'.")
            else:
                self.error(26, f"Error at line {self.current_line}: Variable '{list_name}' is not a list.")
        elif expression.startswith("all(") and expression.endswith(")"):
            list_name = expression[4:-1]
            if list_name in self.variables and isinstance(self.variables[list_name], list):
                return "".join(map(str, self.variables[list_name]))
            else:
                self.error(27, f"Error at line {self.current_line}: List '{list_name}' is not defined.")
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
            self.ret_val = None
            debuger.debug_interpret_func(expression) if self.debug == True else self.interpret(expression)
            return self.ret_val
        elif expression.startswith("char(") and expression.endswith(")"):
            return chr(self.evaluate_expression(expression[5:-1]))
        elif expression.startswith("join(") and expression.endswith(")"):
            char, value = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', expression[5:-1])
            char = self.evaluate_expression(char)
            value = self.evaluate_expression(value)
            return char.join(value)
        elif expression.startswith("addr(") and expression.endswith(")"):
            target = self.evaluate_expression(expression[5:-1])
            resolved_addr = None
            if isinstance(target, Reference):
                if target.addr is not None:
                    resolved_addr = target.addr
                else:
                    raw = self.variables.get_raw(target.var_name)
                    if isinstance(raw, MemoryPointer):
                        resolved_addr = raw.addr
            elif isinstance(target, MemoryPointer):
                resolved_addr = target.addr
            if resolved_addr is None:
                self.error(59, f"Error at line {self.current_line}: addr() requires a manual memory reference")
                return None
            return resolved_addr
        elif expression.startswith("defined(") and expression.endswith(")"):
            name = expression[8:-1]
            return name in self.variables or name in self.locals or name in self.functions
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
            args = self.evaluate_expression(expression[10:-1]).split(',')
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
        elif "." in expression and not expression.split(".", 1)[0].isdigit():
            in_str = False
            bracket_depth = 0
            split_pos = -1
            for i, ch in enumerate(expression):
                if ch == '"':
                    in_str = not in_str
                elif ch == '[' and not in_str:
                    bracket_depth += 1
                elif ch == ']' and not in_str:
                    if bracket_depth > 0:
                        bracket_depth -= 1
                elif ch == '.' and not in_str and bracket_depth == 0:
                    split_pos = i
                    break
            if split_pos != -1:
                name = expression[:split_pos]
                field = expression[split_pos+1:]
                return self.acces_field(name, field)
            else:
                name, field = expression.split(".", 1)
                return self.acces_field(name, field)
        elif expression.startswith("&"):
            target = expression[1:]
            addr = None
            raw = self.variables.get_raw(target)
            if isinstance(raw, MemoryPointer):
                addr = raw.addr
            if target in self.variables:
                return Reference(target, addr)
            elif target in self.locals:
                return Reference(target)
            elif target in self.functions:
                return FuncReference(target)
        elif expression.startswith("*"):
            ref = self.evaluate_expression(expression[1:])
            if isinstance(ref, Reference):
                if ref.addr is not None and self.manual_memory_enabled:
                    return self.manual_memory_manager.read(ref.addr)
                if ref.var_name in self.variables:
                    return self.variables[ref.var_name]
                elif ref.var_name in self.locals:
                    for i in range(len(self.function_tracker) - 1, -1, -1):
                        for val, func_name, func_id in reversed(self.locals[ref.var_name]):
                            return val
                else:
                    self.error(37, f"Error at line {self.current_line}: Referenced variable '{ref.var_name}' no longer exists")
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
        elif "==" in expression:
            value1 = self.evaluate_expression(expression.split("==")[0].strip())
            value2 = self.evaluate_expression(expression.split("==")[1].strip())
            return value1 == value2
        elif "!=" in expression:
            value1 = self.evaluate_expression(expression.split("!=")[0].strip())
            value2 = self.evaluate_expression(expression.split("!=")[1].strip())
            return value1 != value2
        elif "<=" in expression:
            value1 = self.evaluate_expression(expression.split("<=")[0].strip())
            value2 = self.evaluate_expression(expression.split("<=")[1].strip())
            return value1 <= value2
        elif ">=" in expression:
            value1 = self.evaluate_expression(expression.split(">=")[0].strip())
            value2 = self.evaluate_expression(expression.split(">=")[1].strip())
            return value1 >= value2
        elif "<" in expression:
            value1 = self.evaluate_expression(expression.split("<")[0].strip())
            value2 = self.evaluate_expression(expression.split("<")[1].strip())
            return value1 < value2
        elif ">" in expression:
            value1 = self.evaluate_expression(expression.split(">")[0].strip())
            value2 = self.evaluate_expression(expression.split(">")[1].strip())
            return value1 > value2
        elif expression.startswith("pop"):
            list_name = expression[3:].strip()
            return self.variables[list_name].pop()
        elif expression in self.variables or expression in self.locals:
            if expression in self.locals:
                for i in range(len(self.function_tracker) - 1, -1, -1):
                    for val, func_name, func_id in reversed(self.locals[expression]):
                        if func_name == self.function_tracker[i] and func_id == self.function_ids[i]:
                            return val
            if expression in self.variables:
                return self.variables[expression]
            else:
                self.error(36, f"Error at line {self.current_line}: Variable '{expression}' not found in current scope.")
        else:
            try:
                return eval(expression, {}, self.variables)
            except NameError:
                self.error(28, f"Error at line {self.current_line}: Unknown variable or expression: {expression}")
        return None

    def acces_field(self, name, field):
        name = name.strip()
        base_tokens = re.findall(r"[a-zA-Z_]\w*|\[\s*[^\]]+\s*\]", name)

        if not base_tokens:
            if name in self.variables:
                obj = self.variables[name]
            else:
                self.error(36, f"Error at line {self.current_line}: Variable '{name}' not found in current scope.")
                return None
        else:
            base_var = base_tokens[0]
            obj = None
            if base_var in self.locals:
                for i in range(len(self.function_tracker) - 1, -1, -1):
                    for val, func_name, func_id in reversed(self.locals[base_var]):
                        if func_name == self.function_tracker[i] and func_id == self.function_ids[i]:
                            obj = val
                            break
                    if obj is not None:
                        break
            if obj is None:
                if base_var in self.variables:
                    obj = self.variables[base_var]
                else:
                    self.error(36, f"Error at line {self.current_line}: Variable '{base_var}' not found in current scope.")
                    return None

            if isinstance(obj, Reference):
                if obj.var_name in self.variables:
                    obj = self.variables[obj.var_name]
                else:
                    self.error(37, f"Error at line {self.current_line}: Referenced variable '{obj.var_name}' no longer exists")
                    return None

            for token in base_tokens[1:]:
                if token.startswith('['):
                    index_expr = token[1:-1].strip()
                    index = self.evaluate_expression(index_expr)
                    try:
                        obj = obj[index]
                    except Exception as e:
                        self.error(43, f"Error at line {self.current_line}: Indexing error: {e}")
                        return None

        parts = re.findall(r"\w+|\[.*?\]", field)
        for part in parts:
            if part.startswith('['):
                index_expr = part[1:-1].strip()
                index = self.evaluate_expression(index_expr)
                try:
                    if isinstance(obj, Reference):
                        obj = self.variables.get(obj.var_name)
                    obj = obj[index]
                except Exception as e:
                    self.error(43, f"Error at line {self.current_line}: Indexing error: {e}")
                    return None
            else:
                key = part.strip()
                try:
                    if isinstance(obj, Reference):
                        obj = self.variables.get(obj.var_name)
                    obj = obj[key]
                except Exception:
                    try:
                        if isinstance(obj, Reference):
                            obj = self.variables.get(obj.var_name)
                        obj = getattr(obj, key)
                    except Exception:
                        self.error(44, f"Error at line {self.current_line}: Field '{key}' not found on object")
                        return None
        return obj

    def assign_value_local(self, var_name, expression, ref = False):
        value = self.evaluate_expression(expression)
        if isinstance(value, dict):
            value = value.copy()

        if var_name.startswith("*"):
            ref = self.evaluate_expression(var_name[1:].strip())
            if isinstance(ref, Reference):
                if ref.addr is not None and self.manual_memory_enabled:
                    self.manual_memory_manager.write(ref.addr, value)
                    return
                var_name = ref.var_name

        if "." in var_name:
            tokens = re.findall(r"[a-zA-Z_]\w*|\[\s*[^\]]+\s*\]", var_name)

            if not tokens:
                raise ValueError("Invalid struct field")

            base_var_name = tokens[0]

            target = None
            for i in range(len(self.function_tracker) - 1, -1, -1):
                for item in reversed(self.locals[base_var_name]):
                    if ref == True:
                        target = item[0]
                        break
                    if item[1] == self.function_tracker[i] and item[2] == self.function_ids[i]:
                        target = item[0]
                        break
                if target is not None:
                    break

            if target is None:
                self.error(36, f"Error at line {self.current_line}: Variable '{base_var_name}' not found in current scope.")
                return

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
        elif '[' in var_name:
            base_var = var_name.split('[')[0]
            indexes = re.findall(r'\[(.*?)\]', var_name)

            target = None
            for i in range(len(self.function_tracker) - 1, -1, -1):
                for item in reversed(self.locals[base_var]):
                    if ref == True:
                        target = item[0]
                        break
                    if item[1] == self.function_tracker[i] and item[2] == self.function_ids[i]:
                        target = item[0]
                        break
                if target is not None:
                    break

            if target is None:
                self.error(36, f"Error at line {self.current_line}: Variable '{base_var}' not found in current scope.")
                return

            if isinstance(target, Reference):
                target = self.variables[target.var_name]

            for index_expr in indexes[:-1]:
                index = self.evaluate_expression(index_expr)
                target = target[index]

            last_index = self.evaluate_expression(indexes[-1])
            target[last_index] = value
        else:
            for i in range(len(self.function_tracker) - 1, -1, -1):
                for j, item in enumerate(reversed(self.locals[var_name])):
                    if ref == True:
                        self.locals[var_name][len(self.locals[var_name]) - 1 - j] = (value, item[1], item[2])
                        break
                    if item[1] == self.function_tracker[i] and item[2] == self.function_ids[i]:
                        self.locals[var_name][len(self.locals[var_name]) - 1 - j] = (value, item[1], item[2])
                        return

    def assign_value(self, var_name, expression):
        value = self.evaluate_expression(expression)
        if isinstance(value, dict):
            value = value.copy()

        if var_name.startswith("*"):
            ref = self.evaluate_expression(var_name[1:].strip())
            if isinstance(ref, Reference):
                if ref.addr is not None and self.manual_memory_enabled:
                    self.manual_memory_manager.write(ref.addr, value)
                    return
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

    def increment_var(self, var_name, expression):
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
                target[index] += value
            else:
                target[last_token] += value
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
                target[last_index] += value
            else:
                self.variables[var_name] += value

    def decrement_var(self, var_name, expression):
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
                target[index] -= value
            else:
                target[last_token] -= value
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
                target[last_index] -= value
            else:
                self.variables[var_name] -= value

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
            self.error(29, f"Error at line {self.current_line}: Invalid range expression for loop.")

        self.break_stack.pop()

    def import_functions(self, file_path, alias=None):
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
            self.load_functions_from_file(file_path, alias)
        else:
            if "::" in file_path:
                args = file_path.split("::")
                file = args.pop()
                folder = "/".join(args)
                file_path = f"{PackageManager.user_packages_path}/{folder}/{file}.pryzma"
            else:
                file_path = f"{PackageManager.user_packages_path}/{file_path}/{file_path}.pryzma"
            self.load_functions_from_file(file_path, alias)

    def load_function_from_file(self, file_path, func_name, alias=None):
        if alias:
            name = alias
        else:
            name = os.path.splitext(os.path.basename(file_path))[0]
        try:
            program = None
            with open(file_path, "rb") as f:
                data = f.read()
            if data.startswith("prz".encode('utf-8')):
                program = self.decompress(data[3:])
            if not program:
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
            self.error(30, f"Error at line {self.current_line}: File '{file_path}' not found.")

    def load_functions_from_file(self, file_path, alias=None):
        if alias:
            name = alias
        else:
            name = os.path.splitext(os.path.basename(file_path))[0]
        try:
            unpack = False
            program = None
            with open(file_path, "rb") as f:
                data = f.read()
            if data.startswith("prz".encode('utf-8')):
                program = self.decompress(data[3:])
            if not program:
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
            self.error(30, f"Error at line {self.current_line}: File '{file_path}' not found.")

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
            self.error(31, f"Error at line {self.current_line}: List '{list_name}' does not exist.")

    def pop_from_list(self, list_name, index):
        if list_name in self.variables:
            try:
                index = self.evaluate_expression(index)
                self.variables[list_name].pop(index)
            except IndexError:
                self.error(32, f"Error at line {self.current_line}: Index {index} out of range for list '{list_name}'.")
        else:
            self.error(33, f"Error at line {self.current_line}: List '{list_name}' does not exist.")

    def parse_call_statement(self, statement):
        if statement.startswith("(") and statement.endswith(")"):
            statement = statement[1:-1]
            parts = [part.strip() for part in re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', statement)]

            if len(parts) < 2:
                self.error(34, "Invalid number of arguments for call")

            file_name = self.evaluate_expression(parts[0])
            function_name = self.evaluate_expression(parts[1])

            args = parts[2:]

            for i, arg in enumerate(args):
                args[i] = self.evaluate_expression(arg)

            return file_name, function_name, args
        else:
            self.error(35, "Invalid call statement format. Expected format: call(file_name, function_name, arg1, arg2, ...)")

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
                return func(*args)
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

    def register_c_wildcard_library(self, c_lib):
        if c_lib not in self.c_extern_wildcards:
            self.c_extern_wildcards.append(c_lib)

    def resolve_wildcard_function(self, function_name):
        for c_lib in reversed(self.c_extern_wildcards):
            try:
                c_func = getattr(c_lib, function_name)
            except AttributeError:
                continue
            wrapper = ExternFunction(c_func)
            self.variables[function_name] = wrapper
            return wrapper
        return None

    def resolve_pyextern_module_reference(self, module_expr):
        module_expr = module_expr.strip()

        if module_expr.startswith("\"") and module_expr.endswith("\""):
            return module_expr[1:-1]

        return self.evaluate_expression(module_expr)

    def load_pyextern_module(self, module_ref):
        try:
            if module_ref.endswith(".py") or os.path.sep in module_ref:
                base_file = self.variables.get("__file__", getattr(self, "file_path", os.getcwd()))
                base_dir = os.path.dirname(base_file)

                candidates = []

                if os.path.isabs(module_ref):
                    candidates.append(module_ref)
                else:
                    candidates.append(os.path.abspath(module_ref))
                    candidates.append(os.path.abspath(os.path.join(base_dir, module_ref)))

                module_path = next((path for path in candidates if os.path.isfile(path)), None)
                if module_path is None:
                    print(f"File '{module_ref}' does not exist.")
                    return None

                module_name = f"pryzma_pyextern_{abs(hash(module_path))}"
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                if spec is None or spec.loader is None:
                    print(f"Could not load the module from '{module_path}'.")
                    return None

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module

            return importlib.import_module(module_ref)
        except Exception as e:
            print(f"Error loading python module '{module_ref}': {e}")
            return None

    def parse_pyextern_functions(self, functions_str):
        functions_str = functions_str.strip()
        if not functions_str:
            return []
        if functions_str.startswith("{") and functions_str.endswith("}"):
            raw_entries = re.split(r'[|,]', functions_str[1:-1])
        else:
            raw_entries = [functions_str]

        parsed = []
        for entry in raw_entries:
            entry = entry.strip()
            if not entry:
                continue

            if entry == "*":
                parsed.append(("*", "*"))
                continue

            alias = None
            if " as " in entry:
                func_name, alias = entry.split(" as ", 1)
                func_name = func_name.strip()
                alias = alias.strip()
            else:
                func_name = entry

            alias = alias or func_name.split(".")[-1]
            parsed.append((func_name, alias))
        return parsed

    def resolve_pyextern_callable(self, module, func_path):
        target = module
        for attr in func_path.split('.'):
            if not hasattr(target, attr):
                return None
            target = getattr(target, attr)
        return target

    def bind_all_pyextern_callables(self, module):
        for attr_name in dir(module):
            if attr_name.startswith("_"):
                continue
            try:
                attr = getattr(module, attr_name)
            except AttributeError:
                continue
            if callable(attr):
                self.variables[attr_name] = PyExternFunction(attr)

    def configure_c_function_defaults(self, func_name, c_func):
        lowered = func_name.lower()
        try:
            if lowered == "malloc":
                c_func.argtypes = [ctypes.c_size_t]
                c_func.restype = ctypes.c_void_p
            elif lowered == "calloc":
                c_func.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
                c_func.restype = ctypes.c_void_p
            elif lowered == "realloc":
                c_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                c_func.restype = ctypes.c_void_p
            elif lowered == "free":
                c_func.argtypes = [ctypes.c_void_p]
                c_func.restype = None
            elif lowered in ("memcpy", "memmove"):
                c_func.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
                c_func.restype = ctypes.c_void_p
            elif lowered == "memset":
                c_func.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
                c_func.restype = ctypes.c_void_p
        except Exception:
            pass

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
    v - show all variables
    f - show all functions
    s - show all structs
    l - show all locals
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
11 - Invalid statement
12 - Unknown error
13 - Module does not have a 'start' function.
14 - Error loading module
15 - Error writing to file
16 - Invalid number of arguments for replace function
17 - Invalid number of arguments for resplit function
18 - The first argument of resplit() must be a string (regex pattern).
19 - The second argument of resplit() must be a string.
20 - Invalid regex pattern.
21 - in() function error
22 - Invalid number of arguments for splitby function
23 - File not found
24 - Invalid number of arguments for index function
25 - Value not found in list for index function
26 - Variable is not a list for index function
27 - List not defined for all()
28 - Unknown variable or expression
29 - Invalid range expression for loop
30 - File not found for use function
31 - List does not exist for append function
32 - Index out of range for pop function
33 - List does not exist for pop function
34 - Invalid number of arguments for call.
35 - Invalid call statement format.
36 - Variable not found in current scope.
37 - Referenced variable no longer exists.
38 - Referenced function no longer exists.
39 - Overlaping names of struct instance and one of variables used for destructuring.
40 - Name of a non existing function pased as an argument to patch()
41 - List not found for the foreach function.
42 - 'using' statement can only be used with struct instances.
43 - Indexing Error.
44 - Field not found on object.
"""
)

class Debuger:
    def debug_interpret_while(self, line):
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
        interpreter.break_stack.append(False)
        interpreter.in_loop = True
        lines_map_snapshot = interpreter.lines_map.copy()
        while interpreter.evaluate_expression(condition):
            command = 0
            continue_ = False
            interpreter.lines_map = lines_map_snapshot.copy()
            for action in actions:
                line = action.strip()
                if not line:
                    continue
                for stmt, num in interpreter.lines_map:
                    if line.startswith(stmt.strip()) and stmt.strip() != "":
                        interpreter.lines_map.remove((stmt, num))
                        interpreter.current_line = num + 1
                        break

                if continue_ == False:
                    command_ = input("Debugger> ").strip()
                    if command_ == 's':
                        self.debug_log_message("User chose to step.")
                        self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                        print(f"Debug: Executing line {interpreter.current_line}: {line}")
                        if line.startswith("if"):
                            self.debug_interpret_if(line)
                        elif line.startswith("@"):
                            self.debug_interpret_func(line)
                        elif line.startswith("for") and not line.startswith("foreach"):
                            self.debug_interpret_for(line)
                        elif line.startswith("while"):
                            self.debug_interpret_while(line)
                        elif line.startswith("foreach"):
                            self.debug_interpret_foreach(line)
                        else:
                            interpreter.interpret(line)
                        command += 1
                    elif command_ == 'c':
                        self.debug_log_message("User chose to continue.")
                        continue_ = True
                    elif command_.startswith('b '):
                        try:
                            line_num = int(command_.split()[1])
                            self.breakpoints.add(line_num-1)
                            print(f"Breakpoint added at line {line_num}.")
                            self.debug_log_message(f"Breakpoint added at line {line_num}.")
                        except ValueError:
                            print("Invalid line number. Usage: b <line_number>")
                    elif command_.startswith('r '):
                        try:
                            line_num = int(command_.split()[1])
                            self.breakpoints.discard(line_num)
                            print(f"Breakpoint removed at line {line_num}.")
                            self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                        except ValueError:
                            print("Invalid line number. Usage: r <line_number>")
                    elif command_ == 'l':
                        print("Breakpoints:", sorted(self.breakpoints))
                        self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
                    elif command_ == 'v':
                        print("Variables:", interpreter.variables)
                        self.debug_log_message(f"Variables: {interpreter.variables}")
                    elif command_ == 'f':
                        print("Functions:", interpreter.functions)
                        self.debug_log_message(f"Functions: {interpreter.functions}")
                    elif command_ == 'st':
                        print("Structs:", interpreter.structs)
                        self.debug_log_message(f"Structs: {interpreter.structs}")
                    elif command_.startswith("!!"):
                        exec(command_[2:])
                        self.debug_log_message(f"Run code: {command_[2:]}")
                    elif command_.startswith("!"):
                        interpreter.interpret(command_[1:])
                        print("\n")
                        self.debug_log_message(f"Run code: {command_[1:]}")
                    elif command_ == 'log':
                        self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                        print(f"Logging to {self.log_file}")
                        self.debug_log_message(f"Log file set to: {self.log_file}")
                    elif command_ == 'exit':
                        print("Exiting debugger.")
                        self.debug_log_message("Debugger exited.")
                        exit()
                    elif command_ == 'help':
                        self.debug_print_help()
                    elif command_ == 'clear':
                        if os.name == "posix":
                            os.system('clear')
                        else:
                            os.system('cls')
                    else:
                        print("Unknown command. Type 'help' for a list of commands.")
                else:
                    self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                    interpreter.interpret(line)
                    command += 1
                if interpreter.break_stack[-1]:
                    break
            if interpreter.break_stack[-1]:
                break
        interpreter.break_stack.pop()
        interpreter.in_loop = False

    def debug_interpret_foreach(self, line):
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

        interpreter.break_stack.append(False)
        interpreter.in_loop = True

        if list_name in interpreter.variables:
            lines_map_snapshot = interpreter.lines_map.copy()
            for val in interpreter.variables[list_name]:
                interpreter.variables[loop_var] = val
                command = 0
                continue_ = False
                interpreter.lines_map = lines_map_snapshot.copy()
                for action in actions:
                    line = action.strip()
                    if not line:
                        continue
                    for stmt, num in interpreter.lines_map:
                        if line.startswith(stmt.strip()) and stmt.strip() != "":
                            interpreter.lines_map.remove((stmt, num))
                            interpreter.current_line = num + 1
                            break

                    if continue_ == False:
                        command_ = input("Debugger> ").strip()
                        if command_ == 's':
                            self.debug_log_message("User chose to step.")
                            self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                            print(f"Debug: Executing line {interpreter.current_line}: {line}")
                            if line.startswith("if"):
                                self.debug_interpret_if(line)
                            elif line.startswith("@"):
                                self.debug_interpret_func(line)
                            elif line.startswith("for") and not line.startswith("foreach"):
                                self.debug_interpret_for(line)
                            elif line.startswith("while"):
                                self.debug_interpret_while(line)
                            elif line.startswith("foreach"):
                                self.debug_interpret_foreach(line)
                            else:
                                interpreter.interpret(line)
                            command += 1
                        elif command_ == 'c':
                            self.debug_log_message("User chose to continue.")
                            continue_ = True
                        elif command_.startswith('b '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.add(line_num-1)
                                print(f"Breakpoint added at line {line_num}.")
                                self.debug_log_message(f"Breakpoint added at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: b <line_number>")
                        elif command_.startswith('r '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.discard(line_num)
                                print(f"Breakpoint removed at line {line_num}.")
                                self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: r <line_number>")
                        elif command_ == 'l':
                            print("Breakpoints:", sorted(self.breakpoints))
                            self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
                        elif command_ == 'v':
                            print("Variables:", interpreter.variables)
                            self.debug_log_message(f"Variables: {interpreter.variables}")
                        elif command_ == 'f':
                            print("Functions:", interpreter.functions)
                            self.debug_log_message(f"Functions: {interpreter.functions}")
                        elif command_ == 'st':
                            print("Structs:", interpreter.structs)
                            self.debug_log_message(f"Structs: {interpreter.structs}")
                        elif command_.startswith("!!"):
                            exec(command_[2:])
                            self.debug_log_message(f"Run code: {command_[2:]}")
                        elif command_.startswith("!"):
                            interpreter.interpret(command_[1:])
                            print("\n")
                            self.debug_log_message(f"Run code: {command_[1:]}")
                        elif command_ == 'log':
                            self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                            print(f"Logging to {self.log_file}")
                            self.debug_log_message(f"Log file set to: {self.log_file}")
                        elif command_ == 'exit':
                            print("Exiting debugger.")
                            self.debug_log_message("Debugger exited.")
                            exit()
                        elif command_ == 'help':
                            self.debug_print_help()
                        elif command_ == 'clear':
                            if os.name == "posix":
                                os.system('clear')
                            else:
                                os.system('cls')
                        else:
                            print("Unknown command. Type 'help' for a list of commands.")
                    else:
                        self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                        interpreter.interpret(line)
                        command += 1
                    if interpreter.break_stack[-1]:
                        break
                if interpreter.break_stack[-1]:
                    break
        else:
            interpreter.error(41, f"Error at line {interpreter.current_line}: List not found for the foreach function.")

        interpreter.break_stack.pop()
        interpreter.in_loop = False


    def debug_interpret_for(self, line):
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

        start, end = range_expr.split(":")
        start_val = interpreter.evaluate_expression(start.strip())
        end_val = interpreter.evaluate_expression(end.strip())

        interpreter.break_stack.append(False)
        interpreter.in_loop = True

        if isinstance(start_val, int) and isinstance(end_val, int):
            lines_map_snapshot = interpreter.lines_map.copy()
            for val in range(start_val, end_val):
                interpreter.variables[loop_var] = val
                command = 0
                continue_ = False
                interpreter.lines_map = lines_map_snapshot.copy()
                for action in actions:
                    line = action.strip()
                    if not line:
                        continue
                    for stmt, num in interpreter.lines_map:
                        if line.startswith(stmt.strip()) and stmt.strip() != "":
                            interpreter.lines_map.remove((stmt, num))
                            interpreter.current_line = num + 1
                            break

                    if continue_ == False:
                        command_ = input("Debugger> ").strip()
                        if command_ == 's':
                            self.debug_log_message("User chose to step.")
                            self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                            print(f"Debug: Executing line {interpreter.current_line}: {line}")
                            if line.startswith("if"):
                                self.debug_interpret_if(line)
                            elif line.startswith("@"):
                                self.debug_interpret_func(line)
                            elif line.startswith("for") and not line.startswith("foreach"):
                                self.debug_interpret_for(line)
                            elif line.startswith("while"):
                                self.debug_interpret_while(line)
                            elif line.startswith("foreach"):
                                self.debug_interpret_foreach(line)
                            else:
                                interpreter.interpret(line)
                            command += 1
                        elif command_ == 'c':
                            self.debug_log_message("User chose to continue.")
                            continue_ = True
                        elif command_.startswith('b '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.add(line_num-1)
                                print(f"Breakpoint added at line {line_num}.")
                                self.debug_log_message(f"Breakpoint added at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: b <line_number>")
                        elif command_.startswith('r '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.discard(line_num)
                                print(f"Breakpoint removed at line {line_num}.")
                                self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: r <line_number>")
                        elif command_ == 'l':
                            print("Breakpoints:", sorted(self.breakpoints))
                            self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
                        elif command_ == 'v':
                            print("Variables:", interpreter.variables)
                            self.debug_log_message(f"Variables: {interpreter.variables}")
                        elif command_ == 'f':
                            print("Functions:", interpreter.functions)
                            self.debug_log_message(f"Functions: {interpreter.functions}")
                        elif command_ == 'st':
                            print("Structs:", interpreter.structs)
                            self.debug_log_message(f"Structs: {interpreter.structs}")
                        elif command_.startswith("!!"):
                            exec(command_[2:])
                            self.debug_log_message(f"Run code: {command_[2:]}")
                        elif command_.startswith("!"):
                            interpreter.interpret(command_[1:])
                            print("\n")
                            self.debug_log_message(f"Run code: {command_[1:]}")
                        elif command_ == 'log':
                            self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                            print(f"Logging to {self.log_file}")
                            self.debug_log_message(f"Log file set to: {self.log_file}")
                        elif command_ == 'exit':
                            print("Exiting debugger.")
                            self.debug_log_message("Debugger exited.")
                            exit()
                        elif command_ == 'help':
                            self.debug_print_help()
                        elif command_ == 'clear':
                            if os.name == "posix":
                                os.system('clear')
                            else:
                                os.system('cls')
                        else:
                            print("Unknown command. Type 'help' for a list of commands.")
                    else:
                        self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                        interpreter.interpret(line)
                        command += 1
                    if interpreter.break_stack[-1]:
                        break
                if interpreter.break_stack[-1]:
                    break
        else:
            interpreter.error(29, f"Error at line {interpreter.current_line}: Invalid range expression for loop.")

        interpreter.break_stack.pop()
        interpreter.in_loop = False


    def debug_interpret_func(self, line):
        interpreter.in_func.append(True)
        function_name = line[1:].strip()
        if "(" in function_name:
            function_name, arg = function_name.split("(")
            interpreter.current_func_name = function_name
            arg = arg.strip(")")
            if arg:
                arg = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', arg)
                for args in range(len(arg)):
                    arg[args] = interpreter.evaluate_expression(arg[args].strip())
                interpreter.variables["args"] = arg
        interpreter.function_tracker.append(function_name)
        interpreter.function_ids.append(random.randint(0,100000000))
        if function_name in interpreter.functions:
            try:
                command = 0
                continue_ = False
                interpreter.functions[function_name] = list(filter(None, interpreter.functions[function_name]))
                while command < len(interpreter.functions[function_name]):
                    line = interpreter.functions[function_name][command].strip()
                    if not line:
                        continue
                    for stmt, num in interpreter.lines_map:
                        if line.startswith(stmt.strip()) and stmt.strip() != "":
                            interpreter.lines_map.remove((stmt, num))
                            interpreter.current_line = num + 1
                            break

                    if continue_ == False:
                        command_ = input("Debugger> ").strip()
                        if command_ == 's':
                            self.debug_log_message("User chose to step.")
                            self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                            print(f"Debug: Executing line {interpreter.current_line}: {line}")
                            if line.startswith("if"):
                                self.debug_interpret_if(line)
                            elif line.startswith("@"):
                                self.debug_interpret_func(line)
                            elif line.startswith("for") and not line.startswith("foreach"):
                                self.debug_interpret_for(line)
                            elif line.startswith("while"):
                                self.debug_interpret_while(line)
                            elif line.startswith("foreach"):
                                self.debug_interpret_foreach(line)
                            else:
                                interpreter.interpret(line)
                            command += 1
                        elif command_ == 'c':
                            self.debug_log_message("User chose to continue.")
                            continue_ = True
                        elif command_.startswith('b '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.add(line_num-1)
                                print(f"Breakpoint added at line {line_num}.")
                                self.debug_log_message(f"Breakpoint added at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: b <line_number>")
                        elif command_.startswith('r '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.discard(line_num)
                                print(f"Breakpoint removed at line {line_num}.")
                                self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: r <line_number>")
                        elif command_ == 'l':
                            print("Breakpoints:", sorted(self.breakpoints))
                            self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
                        elif command_ == 'v':
                            print("Variables:", interpreter.variables)
                            self.debug_log_message(f"Variables: {interpreter.variables}")
                        elif command_ == 'f':
                            print("Functions:", interpreter.functions)
                            self.debug_log_message(f"Functions: {interpreter.functions}")
                        elif command_ == 'st':
                            print("Structs:", interpreter.structs)
                            self.debug_log_message(f"Structs: {interpreter.structs}")
                        elif command_.startswith("!!"):
                            exec(command_[2:])
                            self.debug_log_message(f"Run code: {command_[2:]}")
                        elif command_.startswith("!"):
                            interpreter.interpret(command_[1:])
                            print("\n")
                            self.debug_log_message(f"Run code: {command_[1:]}")
                        elif command_ == 'log':
                            self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                            print(f"Logging to {self.log_file}")
                            self.debug_log_message(f"Log file set to: {self.log_file}")
                        elif command_ == 'exit':
                            print("Exiting debugger.")
                            self.debug_log_message("Debugger exited.")
                            exit()
                        elif command_ == 'help':
                            self.debug_print_help()
                        elif command_ == 'clear':
                            if os.name == "posix":
                                os.system('clear')
                            else:
                                os.system('cls')
                        else:
                            print("Unknown command. Type 'help' for a list of commands.")
                    else:
                        self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                        interpreter.interpret(line)
                        command += 1
            finally:
                func_id = interpreter.function_ids[-1]
                if (function_name, func_id) in interpreter.defer_stack:
                    while interpreter.defer_stack[(function_name, func_id)]:
                        deferred = interpreter.defer_stack[(function_name, func_id)].pop()
                        deferred = deferred.split("|")
                        for line in deferred:
                            interpreter.interpret(line.strip())
                if interpreter.gc == True:
                    to_remove = []
                    for var in interpreter.locals:
                        interpreter.locals[var] = [item for item in interpreter.locals[var] if item[2] != func_id]
                        if not interpreter.locals[var]:
                            to_remove.append(var)
                    for var in to_remove:
                        interpreter.locals.pop(var)
        else:
            interpreter.error(3, f"Error at line {interpreter.current_line}: Function '{function_name}' is not defined.")
        interpreter.in_func.pop()
        interpreter.function_tracker.pop()
        interpreter.function_ids.pop()

    def debug_interpret_if(self, line):
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
        if "elif" in line:
            line = list(line)
            depth = 0
            in_str = False
            for i, char in enumerate(line):
                if char == "{" and not in_str:
                    depth += 1
                elif char == "}" and not in_str:
                    depth -= 1
                elif char == '"':
                    in_str = not in_str
                elif depth == 0 and char == "e" and line[i + 1] == "l" and line[i + 2] == "i" and line[i + 3] == "f":
                    line[i] = "#"
                    line[i + 1] = "$"
                    line[i + 2] = "&"
                    line[i + 3] = "@"
            line = "".join(line)
        branches = line.split("#$&@")
        handeled = False
        for branch in branches:
            if handeled == True:
                break
            condition, action = branch.strip()[1:-1].split("){", 1)
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
            if interpreter.evaluate_expression(condition.strip()):
                handeled = True
                command = 0
                continue_ = False
                actions = list(filter(None, actions))
                for action in actions:
                    line = action.strip()
                    if not line:
                        continue
                    for stmt, num in interpreter.lines_map:
                        if line.startswith(stmt.strip()) and stmt.strip() != "":
                            interpreter.lines_map.remove((stmt, num))
                            interpreter.current_line = num + 1
                            break

                    if continue_ == False:
                        command_ = input("Debugger> ").strip()
                        if command_ == 's':
                            self.debug_log_message("User chose to step.")
                            self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                            print(f"Debug: Executing line {interpreter.current_line}: {line}")
                            if line.startswith("@"):
                                self.debug_interpret_func(line)
                            elif line.startswith("if"):
                                self.debug_interpret_if(line)
                            elif line.startswith("for") and not line.startswith("foreach"):
                                self.debug_interpret_for(line)
                            elif line.startswith("while"):
                                self.debug_interpret_while(line)
                            elif line.startswith("foreach"):
                                self.debug_interpret_foreach(line)
                            else:
                                interpreter.interpret(line)
                            command += 1
                        elif command_ == 'c':
                            self.debug_log_message("User chose to continue.")
                            continue_ = True
                        elif command_.startswith('b '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.add(line_num-1)
                                print(f"Breakpoint added at line {line_num}.")
                                self.debug_log_message(f"Breakpoint added at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: b <line_number>")
                        elif command_.startswith('r '):
                            try:
                                line_num = int(command_.split()[1])
                                self.breakpoints.discard(line_num)
                                print(f"Breakpoint removed at line {line_num}.")
                                self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                            except ValueError:
                                print("Invalid line number. Usage: r <line_number>")
                        elif command_ == 'l':
                            print("Breakpoints:", sorted(self.breakpoints))
                            self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
                        elif command_ == 'v':
                            print("Variables:", interpreter.variables)
                            self.debug_log_message(f"Variables: {interpreter.variables}")
                        elif command_ == 'f':
                            print("Functions:", interpreter.functions)
                            self.debug_log_message(f"Functions: {interpreter.functions}")
                        elif command_ == 'st':
                            print("Structs:", interpreter.structs)
                            self.debug_log_message(f"Structs: {interpreter.structs}")
                        elif command_.startswith("!!"):
                            exec(command_[2:])
                            self.debug_log_message(f"Run code: {command_[2:]}")
                        elif command_.startswith("!"):
                            interpreter.interpret(command_[1:])
                            print("\n")
                            self.debug_log_message(f"Run code: {command_[1:]}")
                        elif command_ == 'log':
                            self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                            print(f"Logging to {self.log_file}")
                            self.debug_log_message(f"Log file set to: {self.log_file}")
                        elif command_ == 'exit':
                            print("Exiting debugger.")
                            self.debug_log_message("Debugger exited.")
                            exit()
                        elif command_ == 'help':
                            self.debug_print_help()
                        elif command_ == 'clear':
                            if os.name == "posix":
                                os.system('clear')
                            else:
                                os.system('cls')
                        else:
                            print("Unknown command. Type 'help' for a list of commands.")
                    else:
                        self.debug_log_message(f"Executing line {interpreter.current_line}: {action}")
                        interpreter.interpret(action)
                        command += 1

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
            command = 0
            continue_ = False
            actions = list(filter(None, actions))
            for action in actions:
                line = action.strip()
                if not line:
                    continue
                for stmt, num in interpreter.lines_map:
                    if line.startswith(stmt.strip()) and stmt.strip() != "":
                        interpreter.lines_map.remove((stmt, num))
                        interpreter.current_line = num + 1
                        break

                if continue_ == False:
                    command_ = input("Debugger> ").strip()
                    if command_ == 's':
                        self.debug_log_message("User chose to step.")
                        self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")
                        print(f"Debug: Executing line {interpreter.current_line}: {line}")
                        if line.startswith("@"):
                            self.debug_interpret_func(line)
                        elif line.startswith("if"):
                            self.debug_interpret_if(line)
                        elif line.startswith("for") and not line.startswith("foreach"):
                            self.debug_interpret_for(line)
                        elif line.startswith("while"):
                            self.debug_interpret_while(line)
                        elif line.startswith("foreach"):
                            self.debug_interpret_foreach(line)
                        else:
                            interpreter.interpret(line)
                        command += 1
                    elif command_ == 'c':
                        self.debug_log_message("User chose to continue.")
                        continue_ = True
                    elif command_.startswith('b '):
                        try:
                            line_num = int(command_.split()[1])
                            self.breakpoints.add(line_num-1)
                            print(f"Breakpoint added at line {line_num}.")
                            self.debug_log_message(f"Breakpoint added at line {line_num}.")
                        except ValueError:
                            print("Invalid line number. Usage: b <line_number>")
                    elif command_.startswith('r '):
                        try:
                            line_num = int(command_.split()[1])
                            self.breakpoints.discard(line_num)
                            print(f"Breakpoint removed at line {line_num}.")
                            self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                        except ValueError:
                            print("Invalid line number. Usage: r <line_number>")
                    elif command_ == 'l':
                        print("Breakpoints:", sorted(self.breakpoints))
                        self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
                    elif command_ == 'v':
                        print("Variables:", interpreter.variables)
                        self.debug_log_message(f"Variables: {interpreter.variables}")
                    elif command_ == 'f':
                        print("Functions:", interpreter.functions)
                        self.debug_log_message(f"Functions: {interpreter.functions}")
                    elif command_ == 'st':
                        print("Structs:", interpreter.structs)
                        self.debug_log_message(f"Structs: {interpreter.structs}")
                    elif command_.startswith("!!"):
                        exec(command_[2:])
                        self.debug_log_message(f"Run code: {command_[2:]}")
                    elif command_.startswith("!"):
                        interpreter.interpret(command_[1:])
                        print("\n")
                        self.debug_log_message(f"Run code: {command_[1:]}")
                    elif command_ == 'log':
                        self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                        print(f"Logging to {self.log_file}")
                        self.debug_log_message(f"Log file set to: {self.log_file}")
                    elif command_ == 'exit':
                        print("Exiting debugger.")
                        self.debug_log_message("Debugger exited.")
                        exit()
                    elif command_ == 'help':
                        self.debug_print_help()
                    elif command_ == 'clear':
                        if os.name == "posix":
                            os.system('clear')
                        else:
                            os.system('cls')
                    else:
                        print("Unknown command. Type 'help' for a list of commands.")
                else:
                    self.debug_log_message(f"Executing line {interpreter.current_line}: {action}")
                    interpreter.interpret(action)
                    command += 1

    def debug_print_help(self):
        print("Available commands:")
        for cmd, desc in self.commands_info.items():
            print(f"{cmd}: {desc}")

    def debug_log_message(self, message):
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(message + '\n')

    def debug_interpreter(self, file_path, running_from_file, arguments):
        current_line = 0
        self.breakpoints = set()
        self.log_file = None
        interpreter.variables["argv"] = arguments
        interpreter.variables["__file__"] = os.path.abspath(file_path)

        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        try:
            with open(file_path, 'r') as file:
                program = file.read()
        except FileNotFoundError:
            print(f"File '{file_path}' not found.")
            exit()

        lines = interpreter.preprocess(program)
        interpreter.current_line = 0
        for i in range(0, len(lines)):
            if lines[i].startswith("#replace"):
                a, b = lines[i][8:].split("->")
                a = str(interpreter.evaluate_expression(a.strip()))
                b = str(interpreter.evaluate_expression(b.strip()))
                for i, line in enumerate(lines):
                    lines[i] = re.sub(a, b, line)

        self.commands_info = {
            's': 'Step to the next line',
            'c': 'Continue to the next breakpoint',
            'b <line>': 'Add a breakpoint at the specified line number',
            'r <line>': 'Remove a breakpoint at the specified line number',
            'l': 'List all current self.breakpoints',
            'v': 'View all variables',
            'f': 'View all functions',
            'st': 'View all structs',
            '! <pryzma code>': 'Run some pryzma code',
            'log': 'Set the log file name (default is log.txt)',
            'exit': 'Exit the debugger',
            'help': 'Show this help message'
        }

        print("Debugger started. Type 'help' for a list of commands.")
        self.debug_log_message("Debugger started.")

        while True:
            command = input("Debugger> ").strip()

            if command == 's':
                self.debug_log_message("User chose to step.")
                break
            elif command == 'c':
                self.debug_log_message("User chose to continue to the next breakpoint.")
                break
            elif command.startswith('b '):
                try:
                    line_num = int(command.split()[1])
                    self.breakpoints.add(line_num-1)
                    print(f"Breakpoint added at line {line_num}.")
                    self.debug_log_message(f"Breakpoint added at line {line_num}.")
                except ValueError:
                    print("Invalid line number. Usage: b <line_number>")
            elif command.startswith('r '):
                try:
                    line_num = int(command.split()[1])
                    self.breakpoints.discard(line_num)
                    print(f"Breakpoint removed at line {line_num}.")
                    self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                except ValueError:
                    print("Invalid line number. Usage: r <line_number>")
            elif command == 'l':
                print("Breakpoints:", sorted(self.breakpoints))
                self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
            elif command == 'v':
                print("Variables:", interpreter.variables)
                self.debug_log_message(f"Variables: {interpreter.variables}")
            elif command == 'f':
                print("Functions:", interpreter.functions)
                self.debug_log_message(f"Functions: {interpreter.functions}")
            elif command == 'st':
                print("Structs:", interpreter.structs)
                self.debug_log_message(f"Structs: {interpreter.structs}")
            elif command.startswith("!!"):
                exec(command[2:])
                self.debug_log_message(f"Run code: {command[2:]}")
            elif command.startswith("!"):
                interpreter.interpret(command[1:])
                print("\n")
                self.debug_log_message(f"Run code: {command[1:]}")
            elif command == 'log':
                self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                print(f"Logging to {self.log_file}")
                self.debug_log_message(f"Log file set to: {self.log_file}")
            elif command == 'exit':
                print("Exiting debugger.")
                self.debug_log_message("Debugger exited.")
                exit()
            elif command == 'help':
                self.debug_print_help()
            elif command == 'clear':
                if os.name == "posix":
                    os.system('clear')
                else:
                    os.system('cls')
            else:
                print("Unknown command. Type 'help' for a list of commands.")

        while current_line < len(lines):
            line = lines[current_line].strip()

            for stmt, num in interpreter.lines_map:
                if line.startswith(stmt.strip()) and stmt.strip() != "":
                    interpreter.lines_map.remove((stmt, num))
                    interpreter.current_line = num + 1
                    break

            if interpreter.current_line in self.breakpoints:
                print(f"Breakpoint hit at line {interpreter.current_line}.")
                self.debug_log_message(f"Breakpoint hit at line {interpreter.current_line}.")
            
            if not line.startswith("//") and line != "":
                print(f"Debug: Executing line {interpreter.current_line}: {line}")
                self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")

                try:
                    if line.startswith("@"):
                        self.debug_interpret_func(line)
                    elif line.startswith("if"):
                        self.debug_interpret_if(line)
                    elif line.startswith("for") and not line.startswith("foreach"):
                        self.debug_interpret_for(line)
                    elif line.startswith("while"):
                        self.debug_interpret_while(line)
                    elif line.startswith("foreach"):
                        self.debug_interpret_foreach(line)
                    else:
                        interpreter.interpret(line)
                except Exception as e:
                    error_message = f"Error executing line {interpreter.current_line}: {e}"
                    print(error_message)
                    self.debug_log_message(error_message)
            current_line += 1

            while True:
                command = input("Debugger> ").strip()

                if command == 's':
                    self.debug_log_message("User chose to step.")
                    break
                elif command == 'c':
                    self.debug_log_message("User chose to continue to the next breakpoint.")
                    while current_line < len(lines) and interpreter.current_line not in self.breakpoints:
                        line = lines[current_line].strip()
                        if not line.startswith("//") and line != "":
                            print(f"Debug: Executing line {interpreter.current_line}: {line}")
                            self.debug_log_message(f"Executing line {interpreter.current_line}: {line}")

                            try:
                                if line.startswith("@"):
                                    self.debug_interpret_func(line)
                                elif line.startswith("if"):
                                    self.debug_interpret_if(line)
                                elif line.startswith("for") and not line.startswith("foreach"):
                                    self.debug_interpret_for(line)
                                elif line.startswith("while"):
                                    self.debug_interpret_while(line)
                                elif line.startswith("foreach"):
                                    self.debug_interpret_foreach(line)
                                else:
                                    interpreter.interpret(line)
                            except Exception as e:
                                error_message = f"Error executing line {interpreter.current_line}: {e}"
                                print(error_message)
                                self.debug_log_message(error_message)
                        current_line += 1
                    break
                elif command.startswith('b '):
                    try:
                        line_num = int(command.split()[1])
                        self.breakpoints.add(line_num)
                        print(f"Breakpoint added at line {line_num}.")
                        self.debug_log_message(f"Breakpoint added at line {line_num}.")
                    except ValueError:
                        print("Invalid line number. Usage: b <line_number>")
                elif command.startswith('r '):
                    try:
                        line_num = int(command.split()[1])
                        self.breakpoints.discard(line_num)
                        print(f"Breakpoint removed at line {line_num}.")
                        self.debug_log_message(f"Breakpoint removed at line {line_num}.")
                    except ValueError:
                        print("Invalid line number. Usage: r <line_number>")
                elif command == 'l':
                    print("Breakpoints:", sorted(self.breakpoints))
                    self.debug_log_message(f"Breakpoints listed: {sorted(self.breakpoints)}")
                elif command == 'v':
                    print("Variables:", interpreter.variables)
                    self.debug_log_message(f"Variables: {interpreter.variables}")
                elif command == 'f':
                    print("Functions:", interpreter.functions)
                    self.debug_log_message(f"Functions: {interpreter.functions}")
                elif command == 'st':
                    print("Structs:", interpreter.structs)
                    self.debug_log_message(f"Structs: {interpreter.structs}")
                elif command.startswith("!!"):
                    exec(command[2:])
                    self.debug_log_message(f"Run code: {command[2:]}")
                elif command.startswith("!"):
                    interpreter.interpret(command[1:])
                    print("\n")
                    self.debug_log_message(f"Run code: {command[1:]}")
                elif command == 'log':
                    self.log_file = input("Enter log file name (press Enter for 'log.txt'): ").strip() or 'log.txt'
                    print(f"Logging to {self.log_file}")
                    self.debug_log_message(f"Log file set to: {self.log_file}")
                elif command == 'exit':
                    print("Exiting debugger.")
                    self.debug_log_message("Debugger exited.")
                    exit()
                elif command == 'help':
                    self.debug_print_help()
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
                interpreter.variables.clear()
                interpreter.functions.clear()
                interpreter.structs.clear()

class PackageManager:
    user_packages_path = os.path.dirname(os.path.abspath(__file__)) + "/packages/"
    package_api_url = "http://pryzma.dzordz.pl/download"

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


    def install_package(self, package_name, url = package_api_url):
        package_url = f"{url}/{package_name}"
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
                print(f"Primary source failed: {package_url}")
                print("Trying fallback source (GitHub)...")

                github_repo_url = "https://github.com/IgorCielniak/Pryzma-packages"
                clone_dir = os.path.join("/tmp", f"ppm_temp_{package_name}")

                import_err = False
                try:
                    import subprocess
                except ImportError:
                    import_err = True
                    print("module requests not found")

                if not import_err:
                    try:
                        subprocess.run(["git", "clone", "--depth=1", github_repo_url, clone_dir], check=True)
                        package_folder = os.path.join(clone_dir, package_name)
                        if not os.path.isdir(package_folder):
                            raise FileNotFoundError(f"Package '{package_name}' not found in GitHub repo.")

                        package_path = os.path.join(self.user_packages_path, package_name)

                        if os.path.exists(package_path):
                            shutil.rmtree(package_path)

                        shutil.copytree(package_folder, package_path)
                        print(f"{package_name} installed successfully from GitHub.")
                    except Exception as e:
                        print(f"Fallback source failed: {e}")
                        print("Package installation failed from both sources.")
                    finally:
                        if os.path.exists(clone_dir):
                            shutil.rmtree(clone_dir)

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
    - list <avaliable> <url>: List all installed packages, optinally pass 'avaliable' to see all avalible to download instaed of allready installed ones, and url option to download from a custom server.
    - from url [package_name, package_name]: install packages from a custom server.
    - install [<package_name>, <package_name>]: Install packages from the repository.
    - update [<package_name>, <package_name>]: Update specified packages or all packages if no name is provided.
    - show [<package_name>, <package_name>]: Show information about specific packages or all packages if no name is provided.
    - help: Show this help message.
    - exit: Exit the Pryzma package manager.
        """
        print(help_text)


    def fetch_and_print_packages(self, url = "http://pryzma.dzordz.pl/api/fetch"):
        import_err = False
        try:
            import requests
        except ImportError:
            import_err = True
            print("module requests not found")
        if not import_err:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    package_list = response.json()
                    if package_list:
                        print("Available packages:")
                        for package in package_list:
                            print("-", package)
                    else:
                        print("No packages available on the server.")
                else:
                    print("Failed to fetch packages from the server. Status code:", response.status_code)
            except requests.exceptions.RequestException as e:
                print("Error fetching packages:", e)

    def execute_ppm_command(self,user_input):
        if user_input[0] == "help":
            self.display_help(PackageManager)
        elif user_input[0] == "remove":
            if len(user_input) > 1:
                self.remove_package(PackageManager, user_input[1])
            else:
                print("Please provide a package name.")
        elif user_input[0] == "list":
            if len(user_input) > 1 and user_input[1] == "avaliable":
                if len(user_input) > 2:
                    url = user_input[2]
                    self.fetch_and_print_packages(PackageManager, url)
                else:
                    self.fetch_and_print_packages(PackageManager)
            else:
                self.list_packages(PackageManager)
        elif user_input[0] == "from":
            if len(user_input) > 2:
                url = user_input[1]
                for package in user_input[2:]:
                    self.install_package(PackageManager, package, url)
            else:
                print("Please provide a url and package name.")
        elif user_input[0] == "install":
            if len(user_input) > 1:
                for package in user_input[1:]:
                    self.install_package(PackageManager, package)
            else:
                print("Please provide a package name.")
        elif user_input[0] == "update":
            if len(user_input) > 1:
                for package in user_input[1:]:
                    self.update_package(PackageManager, package)
            else:
                self.update_package(PackageManager)
        elif user_input[0] == "show":
            if len(user_input) > 1:
                for package in user_input[1:]:
                    self.get_package_info(PackageManager, package)
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
    elif code == "v":
        print("variables:", interpreter.variables, "\n")
    elif code == "f":
        print("functions:", interpreter.functions, "\n")
    elif code == "s":
        print("structs:", interpreter.structs, "\n")
    elif code == "l":
        print("locals:", interpreter.locals, "\n")
    else:
        for line in interpreter.preprocess(code):
            interpreter.interpret(line)




def main():
    global interpreter
    global debuger
    global history
    global running_from_file
    global version

    interpreter = PryzmaInterpreter()
    debuger = Debuger()

    history = []
    running_from_file = False
    version = 6.1

    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        arguments = sys.argv[1:]
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
    -pk - output a packed version of a given file to stdout (recomended ext is .prz)
    -upk - output an unpacked version of a given file to stdout
    -upi - unpack and interpret the given file (content of packed files is prefixed with prz so its automaticly recognized and this flag isn't needed most of the time)
                    """)
                    sys.exit()
                if arg == "-d":
                    arguments.remove(arg)
                    interpreter.debug = True
                    debuger.debug_interpreter(file_path, running_from_file, arguments)
                if arg == "-p":
                    interpreter.preprocess_only = True
                if arg == "-np":
                    interpreter.no_preproc = True
                if arg == "-l":
                    interpret_line = True
                if arg == "-fd":
                    interpreter.forward_declare = True
                if arg == "-pk":
                    sys.stdout.buffer.write(interpreter.pack(file_path))
                    sys.exit()
                if arg == "-upk":
                    print(interpreter.unpack(file_path))
                    sys.exit()
                if arg == "-upi":
                    interpreter.unpack_ = True
                    arguments.remove(arg)
        if interpreter.debug == False:
            interpreter.interpret_file(file_path, *arguments)
        sys.exit()

    if not sys.stdin.isatty():
        prog = ""
        for line in sys.stdin:
            prog += line
        interpreter.interpret(prog)
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
