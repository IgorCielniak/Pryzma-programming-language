from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import *
import re

class X86Emulator:
    def __init__(self):
        # Constants
        self.BASE_ADDR = 0x1000000
        self.MEM_SIZE = 2 * 1024 * 1024  # 2MB
        self.STACK_ADDR = self.BASE_ADDR + self.MEM_SIZE - 0x1000
        
        self.register_order = [
            UC_X86_REG_RAX, 
            UC_X86_REG_RBX, 
            UC_X86_REG_RCX,
            UC_X86_REG_RDX, 
            UC_X86_REG_RSI, 
            UC_X86_REG_RDI
        ]

    def _get_reg_name(self, uc_reg):
        return {
            UC_X86_REG_RAX: 'rax',
            UC_X86_REG_RBX: 'rbx',
            UC_X86_REG_RCX: 'rcx',
            UC_X86_REG_RDX: 'rdx',
            UC_X86_REG_RSI: 'rsi',
            UC_X86_REG_RDI: 'rdi',
        }.get(uc_reg, 'unknown')

    def _parse_script(self, script: str, variables: dict):
        asm_code = ""
        asm_match = re.search(r'asm\s*{(.*?)}', script, re.DOTALL)
        if asm_match:
            asm_code = asm_match.group(1).strip()
        return asm_code

    def _resolve_variables(self, asm: str, variables: dict):
        reg_map = {}
        mem_map = {}
        resolved_asm = asm
        mem_cursor = 0x1000  # Relative to BASE_ADDR

        for i, (var, val) in enumerate(variables.items()):
            if i < len(self.register_order):
                reg = self.register_order[i]
                reg_map[var] = (reg, val)
                resolved_asm = re.sub(rf'\b{var}\b', self._get_reg_name(reg), resolved_asm)
            else:
                addr = self.BASE_ADDR + mem_cursor
                mem_map[var] = (addr, val)
                resolved_asm = re.sub(rf'\b{var}\b', f"[{hex(addr)}]", resolved_asm)
                mem_cursor += 8  # Move to next slot

        return resolved_asm, reg_map, mem_map

    def _assemble(self, asm: str) -> bytes:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, _ = ks.asm(asm)
        return bytes(encoding)

    def _emulate(self, code: bytes, reg_map: dict, mem_map: dict):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(self.BASE_ADDR, self.MEM_SIZE)
        mu.mem_write(self.BASE_ADDR, code)
        mu.reg_write(UC_X86_REG_RSP, self.STACK_ADDR)

        for reg, val in reg_map.values():
            mu.reg_write(reg, val)

        for addr, val in mem_map.values():
            mu.mem_write(addr, val.to_bytes(8, 'little'))

        try:
            mu.emu_start(self.BASE_ADDR, self.BASE_ADDR + len(code))
        except Exception as e:
            print("Emulation error:", e)

        results = {}
        for name, (reg, _) in reg_map.items():
            val = mu.reg_read(reg)
            results[name] = val

        for name, (addr, _) in mem_map.items():
            val = int.from_bytes(mu.mem_read(addr, 8), 'little')
            results[name] = val

        return results

    def run(self, script: str, variables: dict):
        asm = self._parse_script(script, variables)
        resolved_asm, reg_map, mem_map = self._resolve_variables(asm, variables)
        code = self._assemble(resolved_asm)
        return self._emulate(code, reg_map, mem_map)
