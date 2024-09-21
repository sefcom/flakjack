import logging
import os
import pathlib
import random
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Dict, List, Tuple, Union

import capstone
import pwn

from .exceptions import GDBSocketNotFoundException
from .gdb_wrapper import GDBWrapper


logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)


class PatchGenerator():
    def __init__(self, target: pathlib.Path, target_opts: List[str]) -> None:
        self.target = target
        self.target_opts = target_opts
        self._target_elf = pwn.ELF(self.target)
        self._gdb_session = None
        self._functions_ignore_crashes = ["abort", "assert"]
        self._unsupported_instr_capstone_grps = ("aes", "avx", "bwi", "cdi", "eri", "fc16", "fma", "hle", "mmx", "rtm",
                                                 "sha", "sse", "ssse", "pclmul", "xop", "cdi", "pfi", "vlx", "fpu",
                                                 "novlx")
        self._mem_mapping = None
        self._binary_exec_timeout = 30  # seconds
        self._patcherex_data_segment_start = 0x07000000
        self._data_bytes_inserted = 0
        self._readable_region = None
        self._writeable_region = None

    def update_target(self, new_target: pathlib.Path) -> None:
        logger.info("New target %s", new_target)
        self.target = new_target

    def get_injected_bytes_count(self) -> int:
        return self._data_bytes_inserted

    def handle_crash(self, crashing_input: pathlib.Path, crash_signum: int) -> Dict[str, Union[bool, str, List[Tuple[int, str]]]]:
        ret_val = None
        with tempfile.TemporaryDirectory() as temp_work_dir:
            logger.info("Processing crash input %s", crashing_input.name)
            crash_file = pathlib.Path(os.path.join(temp_work_dir, "crash"))
            shutil.copy(crashing_input, crash_file)
            gdb_ret = self._start_gdb_session(crash_file)
            if not gdb_ret:
                logger.warning("Failed to start gdb session correctly")
                ret_val = {"success": False, "reason": "gdb session failed to start correctly"}
            else:
                gdb_crash_signum = self._gdb_session.get_crash_signum()
                if not gdb_crash_signum:
                    logger.warning("Binary did not crash within gdb(got signal %d, expected %d)", gdb_crash_signum, crash_signum)
                    ret_val = {"success": False, "reason": f"Binary did not crash within gdb(got signal {str(gdb_crash_signum)})"}
                elif gdb_crash_signum != crash_signum:
                    logger.warning("Binary exited with signal %d but expected signal %d", gdb_crash_signum, crash_signum)
                    ret_val = {"success": False, "reason": f"Binary did not crash with expected signal(got {gdb_crash_signum.value} but expected {crash_signum})"}
                elif crash_signum == signal.SIGFPE:
                    ret_val = self._handle_sigfpe()
                elif crash_signum == signal.SIGSEGV:
                    ret_val =  self._handle_sigsegv()
                elif crash_signum == signal.SIGABRT:
                    ret_val = self._handle_sigabrt()
                else:
                    logger.warning("Signal type %d not supported", crash_signum)
                    ret_val = {"success": False, "reason": f"Unsupported signal type {crash_signum}"}

                self._gdb_session.stop()

        return ret_val

    def _is_addr_in_original_binary(self, addr) -> bool:
        return self._target_elf.vaddr_to_offset(addr) is not None

    def _is_unsupported_instr(self, instr: capstone.CsInsn) -> bool:
        for gid in instr.groups:
            gname = instr.group_name(gid)
            if any(x in gname for x in self._unsupported_instr_capstone_grps):
                return True

        return False

    def _find_crash_image(self, crash_addr) -> Union[None, str]:
        """
        Find executable image in process where crash occurred
        """
        for entry in self._mem_mapping:
            if entry["start"] <= crash_addr <= entry["end"]:
                return entry["image"]

    def _handle_sigabrt(self) -> Dict[str, Union[bool, int, str]]:
        crash_addr = self._gdb_session.get_reg_value("rip")
        crash_image = self._find_crash_image(crash_addr)
        if crash_image is None:
            logger.warning("[SIGABRT] Failed to find crashing image (address: 0x%x)", crash_addr)
            return {"success": False, "reason": "Unable to find executable image where crash occurs"}
        elif crash_image == str(self.target):
            if self._is_addr_in_original_binary(crash_addr):
                logger.info("Crash in binary at address: 0x%x", crash_addr)
                return self._patch_sigabrt_in_binary(crash_addr)
            else:
                # Crash at instruction not present in original binary. This might be because crash is at an instruction
                # from original binary that was moved to patch section when patching.
                logger.warning("No instruction at crash address in original binary. Not patching.")
                return {"success": False, "reason": "No instruction at crash address in original binary. Not patching."}
        else:
            logger.info("Crash in %s(address: 0x%x)", os.path.basename(crash_image), crash_addr)
            return self._patch_sigabrt_in_library(crash_addr, crash_image)

    def _handle_sigfpe(self) -> Dict[str, Union[bool, int, str]]:
        crash_addr = self._gdb_session.get_fault_addr()
        crash_image = self._find_crash_image(crash_addr)
        if crash_image is None:
            logger.warning("[SIGFPE] Failed to find crashing image (address: 0x%x)", crash_addr)
            return {"success": False, "reason": "Unable to find executable image where crash occurs"}
        elif crash_image == str(self.target):
            if self._is_addr_in_original_binary(crash_addr):
                logger.info("Crash in binary at address: 0x%x", crash_addr)
                return self._patch_sigfpe_in_binary(crash_addr)
            else:
                # Crash at instruction not present in original binary. This might be because crash is at an instruction
                # from original binary that was moved to patch section when patching.
                logger.warning("No instruction at crash address in original binary. Not patching.")
                return {"success": False, "reason": "No instruction at crash address in original binary. Not patching."}
        else:
            logger.info("Crash in %s(address: 0x%x)", os.path.basename(crash_image), crash_addr)
            return self._patch_sigfpe_in_library(crash_addr, crash_image)

    def _handle_sigsegv(self) -> Dict[str, Union[bool, int, str]]:
        crash_addr = self._gdb_session.get_reg_value("rip")
        crash_image = self._find_crash_image(crash_addr)
        if crash_image is None:
            logger.warning("[SIGSEGV] Failed to find crashing image (address: 0x%x", crash_addr)
            return {"success": False, "reason": "Unable to find executable image where crash occurs"}
        elif crash_image == str(self.target):
            if self._is_addr_in_original_binary(crash_addr):
                logger.info("Crash in binary at address: 0x%x", crash_addr)
                return self._patch_sigsegv_in_binary(crash_addr)
            else:
                # Crash at instruction not present in original binary. This might be because crash is at an instruction
                # from original binary that was moved to patch section when patching.
                logger.warning("No instruction at crash address in original binary. Not patching.")
                return {"success": False, "reason": "No instruction at crash address in original binary. Not patching."}
        else:
            logger.info("Crash in %s(address: 0x%x)", os.path.basename(crash_image), crash_addr)
            return self._patch_sigsegv_in_library(crash_addr, crash_image)

    def _compute_mem_addr(self, instr: capstone.CsInsn, mem_operand: capstone.x86.X86OpMem) -> int:
        base_reg = instr.reg_name(mem_operand.base)
        index_reg = instr.reg_name(mem_operand.index)
        scale = mem_operand.scale
        disp = mem_operand.disp

        base_reg_val = self._gdb_session.get_reg_value(base_reg)
        if index_reg:
            index_reg_val = self._gdb_session.get_reg_value(index_reg)
        else:
            index_reg_val = 0

        return base_reg_val + (index_reg_val * scale) + disp

    def _convert_mem_op_to_str(self, mem_operand: capstone.x86.X86Op, instr: capstone.CsInsn) -> str:
        ret_str = "[" + instr.reg_name(mem_operand.mem.base)
        if mem_operand.mem.index != capstone.x86.X86_REG_INVALID:
            ret_str += f" + {instr.reg_name(mem_operand.mem.index)} * {mem_operand.mem.scale}"

        if mem_operand.mem.disp > 0:
            ret_str += f"+ {mem_operand.mem.disp}"
        elif mem_operand.mem.disp < 0:
            ret_str += f"{str(mem_operand.mem.disp)}"

        return ret_str + "]"

    def _find_readable_region(self) -> Dict[str, Union[int, str]]:
        for mapping in self._mem_mapping:
            if mapping["image"] == str(self.target) and mapping["perms"] & 4 == 4:
                return mapping

    def _find_rw_region(self) -> Dict[str, Union[int, str]]:
        for mapping in self._mem_mapping:
            if mapping["image"] == str(self.target) and mapping["perms"] & 6 == 6:
                return mapping

        raise Exception("Failed to find an RW region with binary code")

    def _gen_mem_read_sigsegv_patch(self, crash_instr: capstone.CsInsn, mem_operand: capstone.x86.X86Op) -> str:
        """
        Check if memory address is readable using write syscall and change it to a readable address if not
        """

        mem_op_str = self._convert_mem_op_to_str(mem_operand, crash_instr)
        base_reg = crash_instr.reg_name(mem_operand.mem.base)
        index_reg = crash_instr.reg_name(mem_operand.mem.index)
        disp = mem_operand.mem.disp
        valid_addr = random.randint(self._writeable_region["start"],
                                    self._writeable_region["end"] - 1 - mem_operand.size) - disp
        sysno_open = 2
        sysno_write = 1
        sysno_close = 3
        patch = f"""
            ; patch_type = sigsegv_mem_read
            push rcx    ; clobbered by syscall instruction
            push r11    ; clobbered by syscall instruction
            push rdx
            push rsi
            push rdi
            push rax
            ; save mem address value on stack
            lea rsi, {mem_op_str}
            push rsi
            ; open("/tmp/fj", O_CREAT | O_WRONLY)
            mov rsi, 0x6a662f706d742f
            push rsi
            xor edx, edx
            mov esi, 65
            mov rdi, rsp
            mov eax, {sysno_open}
            add rsp, 8
            syscall
            pop rsi
            push rax
            ; write(<fd>, <addr>, <size>)
            mov rdx, {mem_operand.size}
            mov rdi, rax
            mov eax, {sysno_write}
            syscall
            ; close(<fd>)
            pop rdi
            push rax
            mov eax, {sysno_close}
            syscall
            ; if `size` bytes written, do not patch
            pop rax
            cmp eax, {mem_operand.size}
            je nopatch
            mov {base_reg}, {hex(valid_addr)}
            """

        if index_reg:
            patch += f"""
                mov {index_reg}, 0
                """

        for reg in ("rax", "rdi", "rsi", "rdx", "r11", "rcx"):
            # Restore registers only if they are not fixed by patch to avoid segfault again
            if reg != base_reg and reg != index_reg:
                patch += f"pop {reg}\n"
            else:
                patch += "add rsp, 8\n"

        patch += f"""
            jmp done
            nopatch:
            pop rax
            pop rdi
            pop rsi
            pop rdx
            pop r11
            pop rcx
            done:
            """

        return patch

    def _gen_sigsegv_mem_write_patch(self, crash_instr: capstone.CsInsn, mem_operand: capstone.x86.X86Op) -> str:
        """
        Check if memory address is writeable using read syscall and change it to a writeable address if not
        """

        mem_op_str = self._convert_mem_op_to_str(mem_operand, crash_instr)
        base_reg = crash_instr.reg_name(mem_operand.mem.base)
        index_reg = crash_instr.reg_name(mem_operand.mem.index)
        disp = mem_operand.mem.disp
        valid_addr = random.randint(self._writeable_region["start"],
                                    self._writeable_region["end"] - 1 - mem_operand.size) - disp

        sysno_close = 3
        sysno_open = 2
        sysno_read = 0
        patch = f"""
            ; patch_type = sigsegv_mem_write
            push rcx    ; clobbered by syscall instruction
            push r11    ; clobbered by syscall instruction
            push rdx
            push rsi
            push rdi
            push rax
            ; save mem address value on stack
            lea rsi, {mem_op_str}
            push rsi
            ; open("/dev/random", O_RDONLY)
            mov esi, 0x6d6f64
            push rsi
            mov rsi, 0x6e61722f7665642f
            push rsi
            xor edx, edx
            mov esi, 0
            mov rdi, rsp
            mov eax, {sysno_open}
            add rsp, 16
            syscall
            pop rsi
            push rax
            ; read(<fd>, <addr>, <size>)
            mov rdx, {mem_operand.size}
            mov rdi, rax
            mov eax, {sysno_read}
            syscall
            ; close(<fd>)
            pop rdi
            push rax
            mov eax, {sysno_close}
            syscall
            ; if `size` bytes read, do not patch
            pop rax
            cmp eax, {mem_operand.size}
            je nopatch
            mov {base_reg}, {hex(valid_addr)}
            """

        if index_reg:
            patch += f"""
                mov {index_reg}, 0
                """

        for reg in ("rax", "rdi", "rsi", "rdx", "r11", "rcx"):
            # Restore registers only if they are not fixed by patch to avoid segfault again
            if reg != base_reg and reg != index_reg:
                patch += f"pop {reg}\n"
            else:
                patch += "add rsp, 8\n"

        patch += f"""
            jmp done
            nopatch:
            pop rax
            pop rdi
            pop rsi
            pop rdx
            pop r11
            pop rcx
            done:
            """

        return patch

    def _gen_lib_func_two_ptr_arg_sigsegv_skip_patch(self, func_call_instr_addr: int, func_name: str) -> str:
        """
        Check if all bytes from start to end of source and destination are mapped. If any are not, skip function.
        """

        page_size = 0x1000
        sysno_madvise = 28
        if func_name in ("bcmp", "memcmp"):
            # Generate a random return value if skipping the call
            ret_val = random.choice([0, 1])
        else:
            ret_val = None

        patch = f"""
            ; patch_type = sigsegv_{func_name}
            push rcx    ; clobbered by syscall instruction
            push r11    ; clobbered by syscall instruction
            push rdx
            push rsi
            push rax
            push rdi
            push rbx
            push r12
            push r13
            ; save arguments for use later
            mov rbx, rdi
            mov r12, rsi
            mov r13, rdx
            ; check if all destination bytes are valid using madvise
            ; compute start address of page with first byte of destination pointer
            mov rdx, {page_size - 1}
            not rdx
            and rdi, rdx
            ; compute end address of page with last byte of destination pointer and thus, number of bytes to check
            lea rsi, [rbx + r13 + {page_size}]
            and rsi, rdx
            sub rsi, rdi
            mov rdx, 0
            mov rax, {sysno_madvise}
            syscall
            cmp eax, 0
            jl skip_memcpy
            ; check if all source bytes are valid using madvise
            ; compute start address of page with first byte of source pointer
            mov rdi, r12
            mov rdx, {page_size - 1}
            not rdx
            and rdi, rdx
            ; compute end address of page with last byte of source pointer and thus, number of bytes to check
            lea rsi, [r12 + r13 + {page_size}]
            and rsi, rdx
            sub rsi, rdi
            mov rdx, 0
            mov rax, {sysno_madvise}
            syscall
            cmp eax, 0
            jge done
            skip_memcpy:
        """

        if ret_val:
            patch += f"mov rax, {ret_val}"

        patch += f"""
                pop r13
                pop r12
                pop rbx
                pop rdi
                pop rax
                pop rsi
                pop rdx
                pop r11
                pop rcx
                jmp {func_call_instr_addr + 5}
            done:
                pop r13
                pop r12
                pop rbx
                pop rdi
                pop rax
                pop rsi
                pop rdx
                pop r11
                pop rcx
        """

        return patch

    def _gen_ret_sigsegv_patch(self, crash_addr: int) -> List[Tuple[int, str]]:
        """
        Generate patch for SIGSEGV at ret instruction likely caused by return address overwrite. Two patches are
        returned: one to insert at start of block saving return address and other to insert at end of block restoring
        return address if corrupted
        """

        data_addr = self._patcherex_data_segment_start + self._data_bytes_inserted
        self._data_bytes_inserted += self._target_elf.bytes
        func_start_addr = self._gdb_session.get_func_addr(self._gdb_session.get_top_stack_frame().function().name)
        func_end_addr = crash_addr

        func_entry_patch = f"""
        ; patch_type = sigsegv_ret_entry
        push rdi
        mov rdi, [rsp + {self._target_elf.bytes}]
        mov [{data_addr}], rdi
        pop rdi
        """

        func_exit_patch = f"""
        ; patch_type = sigsegv_ret_exit
        push rsi
        push rdi
        mov rdi, [rsp + {2 * self._target_elf.bytes}]
        mov rsi, [{data_addr}]
        cmp rdi, rsi
        je nopatch
        mov [rsp + {2 * self._target_elf.bytes}], rsi
        nopatch:
            pop rdi
            pop rsi
        """

        return [(func_start_addr, func_entry_patch), (func_end_addr, func_exit_patch)]

    def _gen_lib_func_one_ptr_arg_sigsegv_patch(self, func_name: str) -> str:
        """
        Patch for library functions that accept 1 pointer as argument. Check if page pointer points to is mapped and
        update pointer to point to valid address if pointer destination page is not mapped
        """

        page_size = 0x1000
        sysno_madvise = 28
        # if argument is modified, ensure new value has at least max_str_len mapped bytes
        max_str_len = 100
        valid_addr = random.randint(self._readable_region["start"], self._readable_region["end"] - max_str_len - 1)
        patch = f"""
            ; patch_type = sigsegv_{func_name}
            push rcx    ; clobbered by syscall instruction
            push r11    ; clobbered by syscall instruction
            push rdx
            push rsi
            push rax
            push rdi
            ; madvise(<address of page with string>, <page_size>, MADV_NORMAL)
            mov rdx, {page_size - 1}
            not rdx
            and rdi, rdx
            mov rsi, {page_size}
            mov rdx, 0
            mov rax, {sysno_madvise}
            syscall
            cmp eax, 0
            jge nopatch
            mov rdi, {valid_addr}
            add rsp, 8
            jmp done
            nopatch:
                pop rdi
            done:
                pop rax
                pop rsi
                pop rdx
                pop r11
                pop rcx
            """

        return patch

    def _gen_zero_div_mem_patch(self, mem_op: str, mem_size: int) -> str:
        """
        Set memory value to a randomly generated non-zero value of size <= 32 bits
        """

        actual_mem_op = mem_op.replace("ptr", "")
        max_elem_size = min(mem_size * 8, 32)
        random_value = random.randint(2, 2 ** max_elem_size - 1)
        return f"""
            ; patch_type = zero_div_mem
            cmp {actual_mem_op}, 0
            jne label1
            mov {actual_mem_op}, {random_value}
            label1:
            """

    def _gen_zero_div_reg_patch(self, reg_name: str, reg_size: int):
        """
        Set register to a randomly generated non-zero value of size <= 32 bits
        """

        max_elem_size = min(reg_size * 8, 32)
        random_value = random.randint(2, 2 ** max_elem_size - 1)
        return f"""
            ; patch_type = zero_div_reg
            cmp {reg_name}, 0
            jne label1
            mov {reg_name}, {random_value}
            label1:
            """

    def _get_instrs_at_addr(self, address: int, count: int) -> List[capstone.CsInsn]:
        """
        Return count instructions starting from address
        """

        max_instr_length = 15  # The maximum length of an x86 instruction
        disasm = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        disasm.detail = True
        ret_instrs = []
        instrs = disasm.disasm(self._target_elf.read(address, max_instr_length), address)
        for _ in range(count):
            try:
                ret_instrs.append(next(instrs))
            except StopIteration:
                # Disassembly may have failed
                break

        instrs.close()
        return ret_instrs

    def _get_function_called_by_binary(self) -> Union[Tuple[int, str], Tuple[None, None]]:
        """
        If crash is not in binary, return name of first function not in binary that is invoked by walking the backtrace
        and address of instruction in binary where it is called
        """

        stack_frames = self._gdb_session.get_stack_frames()
        if not stack_frames:
            # Failed to find stack frames. Give up.
            return (None, None)

        binary_mapping = None
        instr_addr = None
        function_name = None
        # Find executable region of binary code
        for entry in self._mem_mapping:
            if entry["image"] == str(self.target) and entry["perms"] & 1 == 1:
                binary_mapping = entry
                break

        for stack_frame in stack_frames:
            if binary_mapping["start"] <= stack_frame.pc() <= binary_mapping["end"]:
                # Found first stack frame corresponding to binary code. Get function name from newer stack frame and
                # return adddress.
                instr_addr = stack_frame.pc() - 5
                function_name = stack_frame.newer().name()
                if not function_name:
                    # Frame does not contain function name info. Retrieve name from disassembly in gdb. Since it's an
                    # external function called from binary, call should go to PLT and gdb will display name of function
                    # corresponding to the PLT entry in the disassembly
                    binary_instr = self._gdb_session.execute(f"x/i {instr_addr}").strip().split('\t')[-1]
                    function_name = binary_instr.split('<')[-1].split('@')[0]

                return (instr_addr, function_name)

        return (None, None)

    def _patch_div_crash(self, crash_instr: capstone.CsInsn) -> Dict[str, Union[bool, str, List[Tuple[int, str]]]]:
        # div instruction
        crash_addr = crash_instr.address
        str_crash_instr = f"{crash_instr.mnemonic} {crash_instr.op_str}".strip()
        if len(crash_instr.operands) > 1:
            logger.warning("[SIGFPE] div instruction with multiple operands not supported(instr: %s)", str_crash_instr)
            return {"success": False, "reason": "div instruction with multiple operands not supported",
                    "instr": f"{crash_instr.mnemonic} {crash_instr.op_str}"}

        operand = crash_instr.operands[0]
        if operand.type == capstone.x86.X86_OP_REG:
            reg_val = self._gdb_session.get_reg_value(crash_instr.reg_name(operand.reg))
            if reg_val != 0:
                logger.warning("[SIGFPE] Expected 0 divisor but got 0x%x", reg_val)
                return {"success": False, "reason": f"Divisor register {hex(reg_val)} not zero",
                        "instr": f"{crash_instr.mnemonic} {crash_instr.op_str}"}
            else:
                patch_asm = self._gen_zero_div_reg_patch(crash_instr.reg_name(operand.reg), operand.size)
                logger.info("[SIGFPE] Generated patch successfully")
                return {"success": True, "patches": [(crash_addr, patch_asm)]}
        elif operand.type == capstone.x86.X86_OP_MEM:
            mem_addr = self._compute_mem_addr(crash_instr, operand.mem)
            mem_val = self._gdb_session.get_mem_value(mem_addr, operand.size)
            if mem_val != 0:
                logger.warning("[SIGFPE] Expected 0 divisor but got 0x%x", mem_val)
                return {"success": False, "reason": f"Divisor memory is {hex(mem_val)} not zero",
                        "instr": f"{crash_instr.mnemonic} {crash_instr.op_str}"}

            patch_asm = self._gen_zero_div_mem_patch(crash_instr.op_str, operand.size)
            logger.info("[SIGFPE] Generated patch successfully")
            return {"success": True, "patches": [(crash_addr, patch_asm)]}
        else:
            logger.warning("[SIGFPE] Operand of type %s not supported", {operand.type})
            return {"success": False, "reason": f"Unsupported operand of type {operand.type} for div instruction",
                    "instr": f"{crash_instr.mnemonic} {crash_instr.op_str}"}

    def _patch_sigabrt_in_binary(self, crash_addr: int) -> Dict[str, Union[bool, int, str]]:
        ret_val = self._get_instrs_at_addr(crash_addr, 1)
        if len(ret_val) < 1:
            # Disassembly failed likely because execution jumped in middle of valid instruction (or maybe a capstone
            # bug?). Stop.
            return{"success": False, "reason": "Failed to extract instruction at crash address.",
                   "instr_addr": hex(crash_addr)}

        crash_instr = ret_val[0]
        str_crash_instr = f"{crash_instr.mnemonic} {crash_instr.op_str}".strip()
        logger.warning("[SIGABRT] Crash in binary at 0x%x. Not supported yet.", crash_addr)
        return {"success": False, "reason": "SIGABRT from binary not yet supported", "instr_addr": hex(crash_addr),
                "instr": str_crash_instr}

    def _patch_sigabrt_in_library(self, crash_addr: int, crash_image: str) -> Dict[str, Union[bool, int, str]]:
        instr_addr, external_func = self._get_function_called_by_binary()
        if external_func is None:
            addr = hex(instr_addr) if instr_addr else "???"
            return {"success": False,
                    "reason": f"Failed to find name of external function called from binary(address {addr})"}

        crash_image_name = os.path.basename(crash_image)
        for afunction in self._functions_ignore_crashes:
            if afunction in external_func:
                logger.info("[SIGABRT] Ignoring crash in %s", external_func)
                return {"success": False, "reason": f"Crashes in {external_func} are ignored"}

        logger.info("[SIGABRT] Crash in %s", external_func)
        logger.warning("[SIGABRT] Crash in %s(from call to %s at 0x%x) not yet supported", crash_image_name, external_func,
                       instr_addr)
        return {"success": False, "reason": f"Crash in {crash_image_name}(from call to {external_func} at " +
                                            f"{hex(instr_addr)}) not yet supported"}

    def _patch_sigfpe_in_binary(self, crash_addr: int) -> Dict[str, Union[bool, int, str]]:
        ret_val = self._get_instrs_at_addr(crash_addr, 1)
        if len(ret_val) < 1:
            # Disassembly failed likely because execution jumped in middle of valid instruction (or maybe a capstone
            # bug?). Stop.
            return{"success": False, "reason": "Failed to extract instruction at crash address.",
                   "instr_addr": hex(crash_addr)}

        crash_instr = ret_val[0]
        str_crash_instr = f"{crash_instr.mnemonic} {crash_instr.op_str}".strip()
        if self._is_unsupported_instr(crash_instr):
            logger.warning("[SIGFPE] Patching instruction %s is not supported", str_crash_instr)
            return {"success": False, "reason": "Crash at unsupported instruction type",
                    "instr": str_crash_instr}
        elif crash_instr.id in (capstone.x86.X86_INS_DIV, capstone.x86.X86_INS_IDIV):
            return self._patch_div_crash(crash_instr)
        else:
            logger.warning("[SIGFPE] Add support for patching crash at %s instruction.", str_crash_instr)
            return {"success": False, "reason": f"Patching {crash_instr.mnemonic} not supported in SIGFPE yet",
                    "instr": str_crash_instr}

    def _patch_sigfpe_in_library(self, crash_addr: int, crash_image: str) -> Dict[str, Union[bool, int, str]]:
        instr_addr, external_func = self._get_function_called_by_binary()
        if external_func is None:
            addr = hex(instr_addr) if instr_addr else "???"
            return {"success": False,
                    "reason": f"Failed to find name of external function called from binary(address: {addr})"}

        crash_image_name = os.path.basename(crash_image)
        for afunction in self._functions_ignore_crashes:
            if afunction in external_func:
                logger.info("[SIGFPE] Ignoring crash in %s", external_func)
                return {"success": False, "reason": f"Crashes in {external_func} are ignored"}

        logger.info("[SIGFPE] Crash in %s", external_func)
        logger.warning("[SIGFPE] Crash in %s(from call to %s at 0x%x) not yet supported", crash_image_name,
                       external_func, instr_addr)
        return {"success": False, "reason": f"Crash in {crash_image_name}(from call to {external_func} at " +
                                            f"{hex(instr_addr)}) not yet supported"}

    def _patch_sigsegv_in_binary(self, crash_addr: int) -> Dict[str, Union[bool, str, List[Tuple[int, str]]]]:
        ret_val = self._get_instrs_at_addr(crash_addr, 1)
        if len(ret_val) < 1:
            # Disassembly failed likely because execution jumped in middle of valid instruction (or maybe a capstone
            # bug?). Stop.
            return{"success": False, "reason": "Failed to extract instruction at crash address.",
                   "instr_addr": hex(crash_addr)}

        crash_instr = ret_val[0]
        str_crash_instr = f"{crash_instr.mnemonic} {crash_instr.op_str}".strip()
        if self._is_unsupported_instr(crash_instr):
            logger.warning("[SIGSEGV] Patching instruction %s is currently not supported", str_crash_instr)
            return {"success": False, "reason": "Crash at unsupported instruction type",
                    "instr": str_crash_instr}

        for gid in crash_instr.groups:
            if crash_instr.group_name(gid) in ("call", "jump"):
                # Target crashed likely because of segfault in argument of call or jump. Not handled currently.
                logger.warning("[SIGSEGV] Crash at call/jump not supported")
                return {"success": False, "reason": "SIGSEGV at call/jump not supported",
                        "instr": str_crash_instr}

        if crash_instr.insn_name() == "push":
            # SIGSEGV caused by stack operations ignored
            logger.warning("[SIGSEGV] Crash at %s not supported", str_crash_instr)
            return {"success": False, "reason": f"SIGSEGV at {crash_instr.insn_name()} instruction not supported",
                    "instr": str_crash_instr}
        elif crash_instr.insn_name() == "ret":
            return {"success": True, "patches": self._gen_ret_sigsegv_patch(crash_addr)}

        mem_operand = None
        for operand in crash_instr.operands:
            if operand.type == capstone.x86.X86_OP_MEM:
                mem_operand = operand
                break
        else:
            logger.warning("[SIGSEGV] Failed to find memory operand in '%s'", str_crash_instr)
            return {"success": False, "reason": "Failed to find memory operand in segfaulting instruction",
                    "instr": str_crash_instr}

        if mem_operand.access == capstone.CS_AC_READ:
            patch_asm = self._gen_mem_read_sigsegv_patch(crash_instr, mem_operand)
        elif mem_operand.access & capstone.CS_AC_WRITE != 0:
            patch_asm = self._gen_sigsegv_mem_write_patch(crash_instr, mem_operand)
        else:
            logger.warning("[SIGSEGV] Unsupported memory access type(%d) at segfaulting instruction", mem_operand.access)
            return {"success": False, "instr": str_crash_instr,
                    "reason": f"Unsupported memory access type({mem_operand.access}) at segfaulting instruction"}

        logger.info("[SIGSEGV] Generated patch successfully")
        return {"success": True, "patches": [(crash_addr, patch_asm)]}

    def _patch_sigsegv_in_library(self, crash_addr: int, crash_image: str) -> Dict[str, Union[bool, str, List[Tuple[int, str]]]]:
        instr_addr, external_func = self._get_function_called_by_binary()
        if external_func is None:
            addr = hex(instr_addr) if instr_addr else "???"
            return {"success": False,
                    "reason": f"Failed to find name of external function called from binary(address: {addr})"}

        crash_image_name = os.path.basename(crash_image)
        for afunction in self._functions_ignore_crashes:
            if afunction in external_func:
                logger.info("[SIGSEGV] Ignoring crash in %s", external_func)
                return {"success": False, "reason": f"Crashes in {external_func} are ignored"}

        logger.info("[SIGSEGV] Crash in %s", external_func)
        if "strchr" in external_func:
            # Crashes in strchr are usually due to string argument being invalid. Update the argument to point to valid
            # data
            patch_asm = self._gen_lib_func_one_ptr_arg_sigsegv_patch("strchr")
            return {"success": True, "patches": [(instr_addr, patch_asm)]}
        elif "memcpy" in external_func:
            # Crashes in memcpy are because either source or destination pointers are invalid because they are corrupted
            # or because count is too high. Do not execute memcpy if that is true.
            patch_asm = self._gen_lib_func_two_ptr_arg_sigsegv_skip_patch(instr_addr, "memcpy")
            return {"success": True, "patches": [(instr_addr, patch_asm)]}
        elif "memmove" in external_func:
            # Crashes in memmove are similar to memcpy: either source or destination pointers are invalid.
            patch_asm = self._gen_lib_func_two_ptr_arg_sigsegv_skip_patch(instr_addr, "memmove")
            return {"success": True, "patches": [(instr_addr, patch_asm)]}
        elif "bcmp" in external_func:
            # Crashes in bcmp are similar to memcpy: either source or destination pointers are invalid.
            patch_asm = self._gen_lib_func_two_ptr_arg_sigsegv_skip_patch(instr_addr, "bcmp")
            return {"success": True, "patches": [(instr_addr, patch_asm)]}
        elif "memcmp" in external_func:
            # memcmp is newer version of deprecated bcmp
            patch_asm = self._gen_lib_func_two_ptr_arg_sigsegv_skip_patch(instr_addr, "memcmp")
            return {"success": True, "patches": [(instr_addr, patch_asm)]}
        elif "strncpy" in external_func:
            patch_asm = self._gen_lib_func_two_ptr_arg_sigsegv_skip_patch(instr_addr, "strncpy")
            return {"success": True, "patches": [(instr_addr, patch_asm)]}
        elif "strlen" in external_func:
            # strlen segfaults because pointer passed to it is not valid.
            patch_asm = self._gen_lib_func_one_ptr_arg_sigsegv_patch("strlen")
            return {"success": True, "patches": [(instr_addr, patch_asm)]}

        logger.warning("[SIGSEGV] Crash in %s(from call to %s at 0x%x) not yet supported", crash_image_name,
                       external_func, instr_addr)
        return {"success": False, "reason": f"Crash in {crash_image_name}(from call to {external_func} at " +
                                            f"{hex(instr_addr)}) not yet supported"}

    def _start_gdb_session(self, crashing_input: pathlib.Path) -> bool:
        """
        Run target in gdb with crashing input and retrieve memory mapping at time of crash
        """

        actual_args = self.target_opts.copy()
        actual_args[actual_args.index("@@")] = crashing_input
        max_number_of_tries = 5
        for attempt_count in range(max_number_of_tries):
            logger.info("Creating a new gdb session (attempt %d of %d)", attempt_count + 1, max_number_of_tries)
            try:
                self._gdb_session = GDBWrapper(self.target, actual_args)
                result = self._gdb_session.run_till_crash(self._binary_exec_timeout)
                if result:
                    logger.info("Successfully started gdb session")
                    break

                self._gdb_session.stop()
            except (ConnectionRefusedError, EOFError, GDBSocketNotFoundException, TimeoutError):
                # GDB socket not found or unable to connect to it possibly because GDB process failed to start. Try
                # again.
                pass

            logger.info("gdb session failed to start")
            time.sleep(1)
        else:
            logger.warning("Failed to start gdb session in %d attempts. Giving up.", max_number_of_tries)
            return False

        logger.info("Retrieving memory mapping from gdb session")
        self._mem_mapping = self._gdb_session.get_mem_mapping()
        if self._mem_mapping is None:
            logger.info("Failed to retrieve memory mapping from gdb session")
            return False

        self._readable_region = self._find_readable_region()
        self._writeable_region = self._find_rw_region()
        logger.info("Successfully retrieved memory mapping from gdb session")
        return True
