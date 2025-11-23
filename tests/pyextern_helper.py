def greet(target="world"):
    return f"hello {target}"

def add(lhs, rhs):
    return lhs + rhs

def repeat(text, count=2, sep=""):
    return sep.join([text] * count)

class Tools:
    @staticmethod
    def triple(value):
        return value * 3
