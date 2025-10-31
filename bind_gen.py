import sys

def main(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith("def"):
                    line = line[3:].strip()
                    func_name, args = line[:-2].split('(')
                    args = args.split(',') if args else []
                    len_args = len(args)
                    args = [f'args[{i}]' for i, arg in enumerate(args)]
                    args = ','.join(args)
                    pryzma_def = f"/{func_name}{{\n"
                    pryzma_def += f"""    return call("{file_path}","{func_name}",{args})\n"""
                    pryzma_def += "}"
                    print(pryzma_def)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bind_gen.py <file_path>")
    else:
        main(sys.argv[1])
