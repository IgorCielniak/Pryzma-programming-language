import ctypes


def _addr(address, offset=0):
    return int(address) + int(offset)


def write_int(address, value):
    ptr = ctypes.c_longlong.from_address(_addr(address))
    ptr.value = int(value)


def read_int(address):
    ptr = ctypes.c_longlong.from_address(_addr(address))
    return ptr.value


def write_int_at(address, offset, value):
    ptr = ctypes.c_longlong.from_address(_addr(address, offset))
    ptr.value = int(value)


def read_int_at(address, offset):
    ptr = ctypes.c_longlong.from_address(_addr(address, offset))
    return ptr.value
