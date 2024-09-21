#!/usr/bin/env python3


import gzip
import pathlib
import pickle
import random
import signal
import subprocess
import unittest

from typing import List, Tuple

import angr

from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import AddRWDataPatch, InsertCodePatch

from flakjack.patch_generator import PatchGenerator


data_dir = pathlib.Path(__file__).resolve().parent / "data"
bins_dir = data_dir / "bins"
cfgs_dir = data_dir / "cfgs"
crash_inps_dir = data_dir / "crashing_inputs"
patches_dir = data_dir / "patches"


class TestPatchGenerator(unittest.TestCase):
    def apply_patches(self, patches: Tuple[int, str], data_size: int, orig_bin: pathlib.Path, patched_bin: pathlib.Path, cfg) -> None:
        patch_objs = []
        for addr, patch_asm in patches:
            patch_objs.append(InsertCodePatch(addr, patch_asm))

        if data_size != 0:
            patch_objs.append(AddRWDataPatch(data_size))

        backend = DetourBackend(str(orig_bin), cfg=cfg)
        backend.apply_patches(patch_objs)
        backend.save(str(patched_bin))

    def check_block(self, project: angr.Project, addr: int, exp_instrs: List[str]) -> bool:
        block = project.factory.block(addr)
        instrs = block.disassembly.insns
        if len(instrs) != len(exp_instrs):
            return False

        for instr, exp_instr in zip(instrs, exp_instrs):
            if f"{instr.mnemonic} {instr.op_str}".rstrip() != exp_instr:
                return False

        return True

    def extract_instrs(self, patch: List[str]) -> List[str]:
        """
        Extract assembly instructions without comments, empty lines, indentation etc
        """
        processed_patch = []
        for aline in (x for x in (y.strip() for y in patch.split('\n')) if x != ''):
            if aline.startswith(';'):
                # Ignore comments
                continue

            if ';' in aline:
                # Strip out comments
                processed_patch.append(aline.split(';')[0].strip())
            else:
                processed_patch.append(aline)

        return processed_patch

    def setUp(self) -> None:
        random.seed(0)

    def test_zero_divide_reg(self):
        """
        Divide by zero with register as divisor
        """

        target = bins_dir / "nm"
        cfg_file = cfgs_dir / "nm.cfg"
        crash_inp = crash_inps_dir / "nm_sigfpe_div0_reg"
        fuzzer_target_opts = ["-A", "-a", "-l", "-S", "--special-syms", "--synthetic", "-D", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGFPE)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ["cmp sil, 0", "jne label1", "mov sil, 218", "label1:"]
        assert(generated_patch[0] == 0x285f86)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "zero_div_reg")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / "nm.patched"
        self.apply_patches(ret_val["patches"], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # First check the block where detour to patch was added
        assert(self.check_block(proj, 0x285f7f, ["nop", "nop", "jmp 0x6000dfd"]))
        # Next check the two blocks with patch
        assert(self.check_block(proj, 0x6000dfd, ["movzx eax, cl", "mov esi, dword ptr [rsp + 0x44]", "cmp sil, 0",
                                                  "jne 0x6000e0d"]))
        assert(self.check_block(proj, 0x6000e0a, ["mov sil, 0xda", "jmp 0x285f86"]))
        # We don't run this patched binary since it is OOM kiled with this crashing input
        patched_bin.unlink()

    def test_zero_divide_mem(self):
        """
        Divide by zero with memory value as divisor
        """

        target = bins_dir / "nm"
        cfg_file = cfgs_dir / "nm.cfg"
        crash_inp = crash_inps_dir / "nm_sigfpe_div0_mem"
        fuzzer_target_opts = ["-A", "-a", "-l", "-S", "--special-syms", "--synthetic", "-D", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGFPE)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ["cmp dword  [rsp + 0x44], 0", "jne label1", "mov dword  [rsp + 0x44], 3626764239", "label1:"]
        assert(generated_patch[0] == 0x2868e1)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "zero_div_mem")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / "nm.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # First check the block where detour to patch was added
        assert(self.check_block(proj, 0x2868d8, ["nop", "nop", "nop", "nop", "jmp 0x6000dfd"]))
        # Next check the two blocks with patch
        assert(self.check_block(proj, 0x6000dfd, ["mov eax, dword ptr [rsp + 0xa8]", "xor edx, edx",
                                                  "cmp dword ptr [rsp + 0x44], 0", "jne 0x6000e15"]))
        assert(self.check_block(proj, 0x6000e0d, ["mov dword ptr [rsp + 0x44], 0xd82c07cf", "jmp 0x2868e1"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

    def test_binary_sigsegv_deref_base_reg_no_restore_collision(self):
        """
        SIGSEGV in binary where memory address is computed using registers not used in patch otherwise
        """

        target = bins_dir / "nm"
        cfg_file = cfgs_dir / "nm.cfg"
        crash_inp = crash_inps_dir / "nm_sigsegv_deref_rbp"
        fuzzer_target_opts = ["-A", "-a", "-l", "-S", "--special-syms", "--synthetic", "-D", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rdi', 'push rax', 'lea rsi, [rbp]',
                          'push rsi', 'mov rsi, 0x6a662f706d742f', 'push rsi',
                          'xor edx, edx', 'mov esi, 65', 'mov rdi, rsp', 'mov eax, 2', 'add rsp, 8', 'syscall',
                          'pop rsi', 'push rax', 'mov rdx, 1', 'mov rdi, rax', 'mov eax, 1', 'syscall', 'pop rdi',
                          'push rax', 'mov eax, 3', 'syscall', 'pop rax', 'cmp eax, 1', 'je nopatch',
                          'mov rbp, 0x3d9058', 'pop rax', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx',
                          'jmp done', 'nopatch:', 'pop rax', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx',
                          'done:']
        assert(generated_patch[0] == 0x285ef2)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_mem_read")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / "nm.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # First check the blocks where detour to patch was added. In this case, there are two blocks: first contains
        # detour while second is partially the original instructions: remaining instructions are along with the patch
        assert(self.check_block(proj, 0x285ef2, ["jmp 0x6000dfd"]))
        assert(self.check_block(proj, 0x285ef7, ["nop", "nop", "nop", "cmp cl, al", "jae 0x285f60"]))
        # Next check the patch. There are 6 blocks in total with the patch and some instructions from original binary
        assert(self.check_block(proj, 0x6000dfd, ["push rcx", "push r11", "push rdx", "push rsi", "push rdi",
                                                  "push rax", "lea rsi, [rbp]", "push rsi",
                                                  "movabs rsi, 0x6a662f706d742f", "push rsi", "xor edx, edx",
                                                  "mov esi, 0x41", "mov rdi, rsp", "mov eax, 2", "add rsp, 8",
                                                  "syscall"]))
        assert(self.check_block(proj, 0x6000e29, ["pop rsi", "push rax", "mov edx, 1", "mov rdi, rax", "mov eax, 1",
                                                  "syscall"]))
        assert(self.check_block(proj, 0x6000e3a, ["pop rdi", "push rax", "mov eax, 3", "syscall"]))
        assert(self.check_block(proj, 0x6000e43, ["pop rax", "cmp eax, 1", "je 0x6000e57"]))
        assert(self.check_block(proj, 0x6000e49, ["mov ebp, 0x3d9058", "pop rax", "pop rdi", "pop rsi", "pop rdx",
                                                  "pop r11", "pop rcx", "jmp 0x6000e5e"]))
        assert(self.check_block(proj, 0x6000e57, ["pop rax", "pop rdi", "pop rsi", "pop rdx", "pop r11", "pop rcx",
                                                  "movzx ecx, byte ptr [rbp]", "lea r13, [rbp + 1]", "jmp 0x285efa"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

    def test_binary_sigsegv_deref_base_reg_restore_collision(self):
        """
        SIGSEGV in binary where memory address is computed using registers used in patch
        """

        target = bins_dir / "nm"
        cfg_file = cfgs_dir / "nm.cfg"
        crash_inp = crash_inps_dir / "nm_sigsegv_deref_rdi"
        fuzzer_target_opts = ["-A", "-a", "-l", "-S", "--special-syms", "--synthetic", "-D", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rdi', 'push rax', 'lea rsi, [rdi]',
                          'push rsi', 'mov rsi, 0x6a662f706d742f', 'push rsi', 'xor edx, edx', 'mov esi, 65',
                          'mov rdi, rsp', 'mov eax, 2', 'add rsp, 8', 'syscall', 'pop rsi', 'push rax', 'mov rdx, 8',
                          'mov rdi, rax', 'mov eax, 1', 'syscall', 'pop rdi', 'push rax', 'mov eax, 3', 'syscall',
                          'pop rax', 'cmp eax, 8', 'je nopatch', 'mov rdi, 0x3d9058', 'pop rax', 'add rsp, 8',
                          'pop rsi', 'pop rdx', 'pop r11', 'pop rcx', 'jmp done', 'nopatch:', 'pop rax', 'pop rdi',
                          'pop rsi', 'pop rdx', 'pop r11', 'pop rcx', 'done:']
        assert(generated_patch[0] == 0x259cdc)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_mem_read")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / "nm.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # First check the blocks where detour to patch was added. In this case, there are two blocks: first contains
        # detour while second is partially the original instructions: remaining instructions are along with the patch
        assert(self.check_block(proj, 0x259cd6, ["nop", "jmp 0x6000dfd"]))
        # Next check the patch. There are 6 blocks in total with the patch and some instructions from original binary
        assert(self.check_block(proj, 0x6000dfd, ["mov byte ptr [rax + 0xa78], cl", "push rcx", "push r11", "push rdx",
                                                  "push rsi", "push rdi", "push rax", "lea rsi, [rdi]", "push rsi",
                                                  "movabs rsi, 0x6a662f706d742f", "push rsi", "xor edx, edx",
                                                  "mov esi, 0x41", "mov rdi, rsp", "mov eax, 2", "add rsp, 8",
                                                  "syscall"]))
        assert(self.check_block(proj, 0x6000e2e, ["pop rsi", "push rax", "mov edx, 8", "mov rdi, rax", "mov eax, 1",
                                                  "syscall"]))
        assert(self.check_block(proj, 0x6000e3f, ["pop rdi", "push rax", "mov eax, 3", "syscall"]))
        assert(self.check_block(proj, 0x6000e48, ["pop rax", "cmp eax, 8", "je 0x6000e5f"]))
        assert(self.check_block(proj, 0x6000e4e, ["mov edi, 0x3d9058", "pop rax", "add rsp, 8", "pop rsi", "pop rdx",
                                                  "pop r11", "pop rcx", "jmp 0x6000e66"]))
        assert(self.check_block(proj, 0x6000e5f, ["pop rax", "pop rdi", "pop rsi", "pop rdx", "pop r11", "pop rcx",
                                                  "jmp 0x259cdc"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

    def test_binary_sigsegv_deref_base_index_reg_restore_collision(self):
        """
        SIGSEGV in binary where memory address is computed using two registers, both used in the patch as well
        """

        target = bins_dir / "nm"
        cfg_file = cfgs_dir / "nm.cfg"
        crash_inp = crash_inps_dir / "nm_sigsegv_deref_rcx_rax"
        fuzzer_target_opts = ["-A", "-a", "-l", "-S", "--special-syms", "--synthetic", "-D", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rdi', 'push rax',
                          'lea rsi, [rcx + rax * 8]', 'push rsi', 'mov rsi, 0x6a662f706d742f', 'push rsi',
                          'xor edx, edx', 'mov esi, 65', 'mov rdi, rsp', 'mov eax, 2', 'add rsp, 8', 'syscall',
                          'pop rsi', 'push rax', 'mov rdx, 8', 'mov rdi, rax', 'mov eax, 1', 'syscall', 'pop rdi',
                          'push rax', 'mov eax, 3', 'syscall', 'pop rax', 'cmp eax, 8', 'je nopatch',
                          'mov rcx, 0x3d9058', 'mov rax, 0', 'add rsp, 8', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11',
                          'add rsp, 8', 'jmp done', 'nopatch:', 'pop rax', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11',
                          'pop rcx', 'done:']
        assert(generated_patch[0] == 0x28856e)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_mem_read")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / "nm.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # First check the blocks where detour to patch was added.
        assert(self.check_block(proj, 0x288567, ["nop", "nop", "jmp 0x6000dfd"]))
        # Next check the patch. There are 6 blocks in total with the patch and some instructions from original binary
        assert(self.check_block(proj, 0x6000dfd, ["mov rcx, qword ptr [rdi + 0x20]", "add eax, -1", "push rcx",
                                                  "push r11", "push rdx", "push rsi", "push rdi", "push rax",
                                                  "lea rsi, [rcx + rax*8]", "push rsi", "movabs rsi, 0x6a662f706d742f",
                                                  "push rsi", "xor edx, edx", "mov esi, 0x41", "mov rdi, rsp",
                                                  "mov eax, 2", "add rsp, 8", "syscall"]))
        assert(self.check_block(proj, 0x6000e30, ["pop rsi", "push rax", "mov edx, 8", "mov rdi, rax", "mov eax, 1",
                                                  "syscall"]))
        assert(self.check_block(proj, 0x6000e41, ["pop rdi", "push rax", "mov eax, 3", "syscall"]))
        assert(self.check_block(proj, 0x6000e4a, ["pop rax", "cmp eax, 8", "je 0x6000e69"]))
        assert(self.check_block(proj, 0x6000e50, ["mov ecx, 0x3d9058", "mov eax, 0", "add rsp, 8", "pop rdi",
                                                  "pop rsi", "pop rdx", "pop r11", "add rsp, 8", "jmp 0x6000e70"]))
        assert(self.check_block(proj, 0x6000e69, ["pop rax", "pop rdi", "pop rsi", "pop rdx", "pop r11", "pop rcx",
                                                  "jmp 0x28856e"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

    def test_rip_relative_addressing_unaffected_by_patching(self):
        """
        Test if patching is done correctly when an instruction using RIP relative addressing is present near patch site.
        Also tests applying multiple patches.
        """

        target = bins_dir / "readelf-for-rip-relative-addressing"
        orig_binary = pathlib.Path(bins_dir / "readelf")
        orig_cfg_file = cfgs_dir / "readelf.cfg"
        crash_inp = crash_inps_dir / "readelf-sigfpe-rip-relative-addressing"
        fuzzer_target_opts = ["-w", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGFPE)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ['cmp cx, 0', 'jne label1', 'mov cx, 55342', 'label1:']
        assert(generated_patch[0] == 0x2a2380)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "zero_div_reg")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with open(orig_cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        readelf_patches_dir = patches_dir / "readelf-rip-relative-addressing"
        patched_bin = target.parent / "readelf.patched"
        previous_patches = [(0x2a3c75, readelf_patches_dir / "1.patch"), (0x29b400, readelf_patches_dir / "2.patch"),
                            (0x2a223c, readelf_patches_dir / "3.patch"), (0x2a2479, readelf_patches_dir / "4.patch")]
        patches = []
        for patch_addr, patch_file in previous_patches:
            with open(patch_file) as fh:
                patches.append((patch_addr, fh.read()))

        patches.append(generated_patch)
        self.apply_patches(patches, patch_gen.get_injected_bytes_count(), orig_binary, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # First check nops after detour
        assert(self.check_block(proj, 0x2a2381, ["nop", "nop", "movzx eax, ax", "movzx ecx, byte ptr [rsp + 0x60]",
                                                 "imul rcx, rax", "add qword ptr [rip + 0x22d222], rcx",
                                                 "mov byte ptr [rip + 0x22d238], dl", "mov esi, 0x20993b",
                                                 "xor edi, edi", "mov edx, 5", "call 0x2c0c90"]))
        assert(self.check_block(proj, 0x2a2375, ["movzx eax, byte ptr [rip + 0x22d258]", "jmp 0x60009c8"]))
        # Next check the two blocks with patch
        assert(self.check_block(proj, 0x60009c8, ["add eax, ebx", "xor edx, edx", "cmp cx, 0", "jne 0x60009d6"]))
        assert(self.check_block(proj, 0x60009d2, ["mov cx, 0xd82e", "div cx", "jmp 0x2a2383"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

    def test_strchr_sigsegv_patch(self):
        """
        Test if SIGSEGV in strchr due to invalid string address is patched correctly
        """

        target = bins_dir / "nm"
        cfg_file = cfgs_dir / "nm.cfg"
        crash_inp = crash_inps_dir / "nm_sigsegv_strchr"
        fuzzer_target_opts = ["-A", "-a", "-l", "-S", "--special-syms", "--synthetic", "-D", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rax', 'push rdi', 'mov rdx, 4095',
                          'not rdx', 'and rdi, rdx', 'mov rsi, 4096', 'mov rdx, 0', 'mov rax, 28', 'syscall',
                          'cmp eax, 0', 'jge nopatch', 'mov rdi, 2198141', 'add rsp, 8', 'jmp done', 'nopatch:',
                          'pop rdi', 'done:', 'pop rax', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx']
        assert(generated_patch[0] == 0x280ff7)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_strchr")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / "nm.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # Check block where detour to patch was added
        assert(self.check_block(proj, 0x280fea, ["mov qword ptr [rsp + 0x60], rbx", "mov rdi, r13", "jmp 0x6000dfd"]))
        # Next check the patch. There are 4 blocks in total with the patch and 1 instruction from original binary
        assert(self.check_block(proj, 0x6000dfd, ["mov esi, 0x3a", "push rcx", "push r11", "push rdx", "push rsi",
                                                  "push rax", "push rdi", "mov edx, 0xfff", "not rdx", "and rdi, rdx",
                                                  "mov esi, 0x1000", "mov edx, 0", "mov eax, 0x1c", "syscall"]))
        assert(self.check_block(proj, 0x6000e25, ["cmp eax, 0", "jge 0x6000e35"]))
        assert(self.check_block(proj, 0x6000e2a, ["mov edi, 0x218a7d", "add rsp, 8", "jmp 0x6000e36"]))
        assert(self.check_block(proj, 0x6000e35, ["pop rdi", "pop rax", "pop rsi", "pop rdx", "pop r11", "pop rcx",
                                                  "jmp 0x280ff7"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

    def test_memcpy_sigsegv_patch(self):
        """
        Test if SIGSEGV in memcpy due to invalid arguments is patched correctly
        """

        target = bins_dir / "MP4Box"
        cfg_file = cfgs_dir / "MP4Box.cfg.gz"
        crash_inp = crash_inps_dir / "mp4box_sigsegv_memcpy"
        fuzzer_target_opts = ["-quiet", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rax', 'push rdi', 'push rbx',
                          'push r12', 'push r13', 'mov rbx, rdi', 'mov r12, rsi', 'mov r13, rdx', 'mov rdx, 4095',
                          'not rdx', 'and rdi, rdx', 'lea rsi, [rbx + r13 + 4096]', 'and rsi, rdx', 'sub rsi, rdi',
                          'mov rdx, 0', 'mov rax, 28', 'syscall', 'cmp eax, 0', 'jl skip_memcpy', 'mov rdi, r12',
                          'mov rdx, 4095', 'not rdx', 'and rdi, rdx', 'lea rsi, [r12 + r13 + 4096]', 'and rsi, rdx',
                          'sub rsi, rdi', 'mov rdx, 0', 'mov rax, 28', 'syscall', 'cmp eax, 0', 'jge done',
                          'skip_memcpy:', 'pop r13', 'pop r12', 'pop rbx', 'pop rdi', 'pop rax', 'pop rsi', 'pop rdx',
                          'pop r11', 'pop rcx', 'jmp 3541378', 'done:', 'pop r13', 'pop r12', 'pop rbx', 'pop rdi',
                          'pop rax', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx']
        assert(generated_patch[0] == 0x36097d)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_memcpy")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with gzip.open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / "MP4Box.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # Check block where detour to patch was added
        assert(self.check_block(proj, 0x360977, ["nop", "jmp 0x6000e5d"]))
        # Next check the patch. There are 4 blocks in total with the patch and 1 instruction from original binary
        assert(self.check_block(proj, 0x6000e5d, ["mov rdx, r13", "mov rbx, r8", "push rcx", "push r11", "push rdx",
                                                  "push rsi", "push rax", "push rdi", "push rbx", "push r12",
                                                  "push r13", "mov rbx, rdi", "mov r12, rsi", "mov r13, rdx",
                                                  "mov edx, 0xfff", "not rdx", "and rdi, rdx",
                                                  "lea rsi, [rbx + r13 + 0x1000]", "and rsi, rdx", "sub rsi, rdi",
                                                  "mov edx, 0", "mov eax, 0x1c", "syscall"]))
        assert(self.check_block(proj, 0x6000e9d, ["cmp eax, 0", "jl 0x6000ecf"]))
        assert(self.check_block(proj, 0x6000ea2, ["mov rdi, r12", "mov edx, 0xfff", "not rdx", "and rdi, rdx",
                                                  "lea rsi, [r12 + r13 + 0x1000]", "and rsi, rdx", "sub rsi, rdi",
                                                  "mov edx, 0", "mov eax, 0x1c", "syscall"]))
        assert(self.check_block(proj, 0x6000eca, ["cmp eax, 0", "jge 0x6000ee0"]))
        assert(self.check_block(proj, 0x6000ecf, ["pop r13", "pop r12", "pop rbx", "pop rdi", "pop rax", "pop rsi",
                                                  "pop rdx", "pop r11", "pop rcx", "jmp 0x360982"]))
        assert(self.check_block(proj, 0x6000ee0, ["pop r13", "pop r12", "pop rbx", "pop rdi", "pop rax", "pop rsi",
                                                  "pop rdx", "pop r11", "pop rcx", "jmp 0x36097d"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 1)
        # Delete patched binary
        patched_bin.unlink()

    def test_ret_sigsegv_patch(self):
        """
        Test if segfault at ret instruction due to buffer overflow is patched correctly
        """

        target = bins_dir / "binary-for-ret-patch"
        crash_inp = crash_inps_dir / "return_addr_overwrite_sigsegv"
        fuzzer_target_opts = ["@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 2)
        generated_patches = ret_val["patches"]
        expected_patch_1 = ['push rdi', 'mov rdi, [rsp + 8]', 'mov [117440512], rdi', 'pop rdi']
        assert(generated_patches[0][0] == 0x401176)
        assert(self.extract_instrs(generated_patches[0][1]) == expected_patch_1)
        expected_patch_2 = ['push rsi', 'push rdi', 'mov rdi, [rsp + 16]', 'mov rsi, [117440512]', 'cmp rdi, rsi',
                            'je nopatch', 'mov [rsp + 16], rsi', 'nopatch:', 'pop rdi', 'pop rsi']
        assert(generated_patches[1][0] == 0x4011f1)
        assert(self.extract_instrs(generated_patches[1][1]) == expected_patch_2)
        patched_bin = target.parent / "binary-for-ret-patch.patched"
        self.apply_patches(generated_patches, patch_gen.get_injected_bytes_count(), target, patched_bin, None)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        # Patch 1
        # Check block after the one where detour to patch was added
        assert(self.check_block(proj, 0x40117b, ["nop", "nop", "nop", "mov dword ptr [rsp + 0xc], edi",
                                                 "mov qword ptr [rsp], rsi", "cmp dword ptr [rsp + 0xc], 2",
                                                 "je 0x401194"]))
        # Check block with detour to patch
        assert(self.check_block(proj, 0x401176, ["jmp 0x600090d"]))
        # Next check the patch.
        assert(self.check_block(proj, 0x600090d, ["push rdi", "mov rdi, qword ptr [rsp + 8]",
                                                  "mov qword ptr [0x7000000], rdi", "pop rdi", "endbr64",
                                                  "sub rsp, 0x48", "jmp 0x40117e"]))
        # Patch 2
        # Check block where detour to patch was added
        assert(self.check_block(proj, 0x4011e8, ["mov eax, 0", "jmp 0x6000929"]))
        # Next check the patch. There are 3 blocks in total with the patch and some instructions from original binary
        assert(self.check_block(proj, 0x6000929, ["add rsp, 0x48", "push rsi", "push rdi",
                                                  "mov rdi, qword ptr [rsp + 0x10]", "mov rsi, qword ptr [0x7000000]",
                                                  "cmp rdi, rsi", "je 0x6000946"]))
        assert(self.check_block(proj, 0x6000941, ["mov qword ptr [rsp + 0x10], rsi", "pop rdi", "pop rsi", "ret"]))
        assert(self.check_block(proj, 0x6000949, ["jmp 0x4011f2"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

    def test_double_ret_sigsegv_patch(self):
        """
        Test if segfault at two ret instructions due to buffer overflow are patched correctly. Tests multiple patches
        using shared data page
        """

        # Patch first crash
        target = bins_dir / "binary-for-double-ret-patch"
        crash_inp = crash_inps_dir / "double_return_addr_overwrite_sigsegv"
        fuzzer_target_opts = ["@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 2)
        generated_patches_1 = ret_val["patches"]
        expected_patch_1_1 = ['push rdi', 'mov rdi, [rsp + 8]', 'mov [117440512], rdi', 'pop rdi']
        assert(generated_patches_1[0][0] == 0x401176)
        assert(self.extract_instrs(generated_patches_1[0][1]) == expected_patch_1_1)
        expected_patch_1_2 = ['push rsi', 'push rdi', 'mov rdi, [rsp + 16]', 'mov rsi, [117440512]', 'cmp rdi, rsi',
                              'je nopatch', 'mov [rsp + 16], rsi', 'nopatch:', 'pop rdi', 'pop rsi']
        assert(generated_patches_1[1][0] == 0x4011da)
        assert(self.extract_instrs(generated_patches_1[1][1]) == expected_patch_1_2)
        patched_bin_1 = target.parent / "1_binary-for-ret-patch.patched"
        self.apply_patches(generated_patches_1, patch_gen.get_injected_bytes_count(), target, patched_bin_1, None)
        # Patch second crash
        patch_gen.update_target(patched_bin_1)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 2)
        generated_patches_2 = ret_val["patches"]
        expected_patch_2_1 = ['push rdi', 'mov rdi, [rsp + 8]', 'mov [117440520], rdi', 'pop rdi']
        assert(generated_patches_2[0][0] == 0x4011db)
        assert(self.extract_instrs(generated_patches_2[0][1]) == expected_patch_2_1)
        expected_patch_2_2 = ['push rsi', 'push rdi', 'mov rdi, [rsp + 16]', 'mov rsi, [117440520]', 'cmp rdi, rsi',
                              'je nopatch', 'mov [rsp + 16], rsi', 'nopatch:', 'pop rdi', 'pop rsi']
        assert(generated_patches_2[1][0] == 0x401215)
        assert(self.extract_instrs(generated_patches_2[1][1]) == expected_patch_2_2)
        patched_bin_2 = target.parent / "2_binary-for-ret-patch.patched"
        self.apply_patches(generated_patches_1 + generated_patches_2, patch_gen.get_injected_bytes_count(), target,
                           patched_bin_2, None)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin_2)
        # Patch for first crash
        # Patch 1
        # Check block after one where detour to patch was added
        assert(self.check_block(proj, 0x40117b, ["nop", "nop", "nop", "mov qword ptr [rsp + 8], rdi",
                                                 "mov rax, qword ptr [rsp + 8]", "lea rdx, [rip + 0xe75]",
                                                 "mov rsi, rdx", "mov rdi, rax", "call 0x401080"]))
        # Check block with detour to patch
        assert(self.check_block(proj, 0x401176, ["jmp 0x60009ad"]))
        # Next check the patch.
        assert(self.check_block(proj, 0x60009ad, ["push rdi", "mov rdi, qword ptr [rsp + 8]",
                                                  "mov qword ptr [0x7000000], rdi", "pop rdi", "endbr64",
                                                  "sub rsp, 0x48", "jmp 0x40117e"]))
        # Patch 2
        # Check block where detour to patch was added
        assert(self.check_block(proj, 0x4011d1, ["nop", "nop", "nop", "nop", "jmp 0x60009c9"]))
        # Next check the patch. There are 2 blocks in total with the patch and some instructions from original binary
        assert(self.check_block(proj, 0x60009c9, ["mov eax, 0", "add rsp, 0x48", "push rsi", "push rdi",
                                                  "mov rdi, qword ptr [rsp + 0x10]", "mov rsi, qword ptr [0x7000000]",
                                                  "cmp rdi, rsi", "je 0x60009eb"]))
        assert(self.check_block(proj, 0x60009e6, ["mov qword ptr [rsp + 0x10], rsi", "pop rdi", "pop rsi", "jmp 0x4011da"]))
        # Patch for second crash
        # Patch 1
        # Check block where detour to patch was added
        assert(self.check_block(proj, 0x4011e0, ["nop", "nop", "nop", "mov dword ptr [rsp + 0xc], edi",
                                                 "mov qword ptr [rsp], rsi", "cmp dword ptr [rsp + 0xc], 2",
                                                 "je 0x4011f9"]))
        assert(self.check_block(proj, 0x4011db, ["jmp 0x60009f2"]))
        # Next check the patch.
        assert(self.check_block(proj, 0x60009f2, ["push rdi", "mov rdi, qword ptr [rsp + 8]",
                                                 "mov qword ptr [0x7000008], rdi", "pop rdi", "endbr64",
                                                 "sub rsp, 0x48", "jmp 0x4011e3"]))
        # Patch 2
        # Check block where detour to patch was added
        assert(self.check_block(proj, 0x40120c, ["mov eax, 0", "jmp 0x6000a0e"]))
        # Next check the patch. There are 3 blocks in total with the patch and some instructions from original binary
        assert(self.check_block(proj, 0x6000a0e, ["add rsp, 0x48", "push rsi", "push rdi",
                                                  "mov rdi, qword ptr [rsp + 0x10]", "mov rsi, qword ptr [0x7000008]",
                                                  "cmp rdi, rsi", "je 0x6000a2b"]))
        assert(self.check_block(proj, 0x6000a26, ["mov qword ptr [rsp + 0x10], rsi", "pop rdi", "pop rsi", "ret"]))
        assert(self.check_block(proj, 0x6000a2e, ["jmp 0x401216"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin_2] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin_1.unlink()
        patched_bin_2.unlink()

    def test_crash_in_patch_section(self):
        """
        Test if crash in patch section is not triaged and ignored.
        """

        target = bins_dir / "tiffcp-for-crash-in-patch-section"
        crash_inp = crash_inps_dir / "tiffcp-crash-in-patch-section"
        orig_bin = bins_dir / "tiffcp"
        fuzzer_target_opts = ["-i", "@@", "/tmp/blah"]
        patch_gen = PatchGenerator(orig_bin, fuzzer_target_opts)
        patch_gen.update_target(target)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(not ret_val["success"])
        assert(ret_val["reason"] == "No instruction at crash address in original binary. Not patching.")

    def test_mem_write_sigsegv(self):
        """
        Test if segfault at memory write instruction is patched correctly
        """

        target = bins_dir / "MP4Box-for-mem-write-sigsegv"
        orig_binary = bins_dir / "MP4Box"
        orig_cfg_file = cfgs_dir / "MP4Box.cfg.gz"
        crash_inp = crash_inps_dir / "mp4box-mem-write-sigsegv"
        fuzzer_target_opts = ["-quiet", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        assert(generated_patch[0] == 0x53ded8)
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rdi', 'push rax', 'lea rsi, [rbx+ 8]',
                          'push rsi', 'mov esi, 0x6d6f64', 'push rsi', 'mov rsi, 0x6e61722f7665642f', 'push rsi',
                          'xor edx, edx', 'mov esi, 0', 'mov rdi, rsp', 'mov eax, 2', 'add rsp, 16', 'syscall',
                          'pop rsi', 'push rax', 'mov rdx, 8', 'mov rdi, rax', 'mov eax, 0', 'syscall', 'pop rdi',
                          'push rax', 'mov eax, 3', 'syscall', 'pop rax', 'cmp eax, 8', 'je nopatch',
                          'mov rbx, 0xa9b9ee', 'pop rax', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx',
                          'jmp done', 'nopatch:', 'pop rax', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx',
                          'done:']
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_mem_write")
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with gzip.open(orig_cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        previous_patches_dir = patches_dir / "mp4box-mem-write-sigsegv"
        patched_bin = target.parent / "MP4Box.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        previous_patches = [(0x3829b8, "1.patch"), (0x382e70, "2-1.patch"), (0x3856f7, "2-2.patch"),
                            (0x387630, "3.patch"), (0x382373, "4.patch"), (0x3876a0, "5.patch"), (0x382a6d, "6.patch"),
                            (0x597152, "7.patch"), (0x5b4690, "8-1.patch"), (0x5b4f44, "8-2.patch")]
        patches = []
        for patch_addr, patch_file in previous_patches:
            with (previous_patches_dir / patch_file).open() as fh:
                patches.append((patch_addr, fh.read()))

        patches.append(generated_patch)
        self.apply_patches(patches, patch_gen.get_injected_bytes_count(), orig_binary, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin, auto_load_libs=False)
        # Check detour to patch
        assert(self.check_block(proj, 0x53ded3, ["jmp 0x600119c"]))
        # Next check the patch. There are 6 blocks in total with the patch and 1 instruction from original binary
        assert(self.check_block(proj, 0x600119c, ['mov rax, qword ptr [rsp + 0x10]', 'push rcx', 'push r11', 'push rdx',
                                                  'push rsi', 'push rdi', 'push rax', 'lea rsi, [rbx + 8]', 'push rsi',
                                                  'mov esi, 0x6d6f64', 'push rsi', 'movabs rsi, 0x6e61722f7665642f',
                                                  'push rsi', 'xor edx, edx', 'mov esi, 0', 'mov rdi, rsp',
                                                  'mov eax, 2', 'add rsp, 0x10', 'syscall']))
        assert(self.check_block(proj, 0x60011d3, ['pop rsi', 'push rax', 'mov edx, 8', 'mov rdi, rax', 'mov eax, 0',
                                                  'syscall']))
        assert(self.check_block(proj, 0x60011e4, ['pop rdi', 'push rax', 'mov eax, 3', 'syscall']))
        assert(self.check_block(proj, 0x60011ed, ['pop rax', 'cmp eax, 8', 'je 0x6001201']))
        assert(self.check_block(proj, 0x60011f3, ['mov ebx, 0xa9b9ee', 'pop rax', 'pop rdi', 'pop rsi', 'pop rdx',
                                                  'pop r11', 'pop rcx', 'jmp 0x6001208']))
        assert(self.check_block(proj, 0x6001201, ['pop rax', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx',
                                                  'jmp 0x53ded8']))
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 1)
        # Delete patched binary
        patched_bin.unlink()

    def test_execution_desync(self):
        """
        Test if patching a crash due to incorrect indirect call target to middle of instruction fails. The desync is not
        100% reliable but seems like copying crash input to temp folder and running, which is what patch generator does,
        reproduces the desync reliably
        """

        target = bins_dir / "MP4Box-for-exec-desync"
        orig_bin = bins_dir / "MP4Box"
        crash_inp = crash_inps_dir / "mp4box-desync-exec"
        fuzzer_target_opts = ["-info", "@@"]
        patch_gen = PatchGenerator(orig_bin, fuzzer_target_opts)
        patch_gen.update_target(target)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(not ret_val["success"])
        assert(ret_val["reason"] == "Failed to extract instruction at crash address.")
        assert(ret_val["instr_addr"] == "0x21d646")

    def test_valid_mem_addr_compute(self):
        """
        Check that sigsegv patching computes a valid memory address correctly when displacement/scale is very large
        """

        target = bins_dir / "ffmpeg-sigsegv-disp-test-case"
        crash_inp = crash_inps_dir / "ffmpeg-sigsegv-disp-test-crash-inp"
        fuzzer_target_opts = ["-y", "-i", "@@", "-c:v", "mpeg4", "-c:a", "copy", "-f", "mp4", "/dev/null"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        assert(generated_patch[0] == 0x7f54c8)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_mem_read")
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rdi', 'push rax',
                          'lea rsi, [rax+ 2337832]', 'push rsi', 'mov rsi, 0x6a662f706d742f', 'push rsi',
                          'xor edx, edx', 'mov esi, 65', 'mov rdi, rsp', 'mov eax, 2', 'add rsp, 8', 'syscall',
                          'pop rsi', 'push rax', 'mov rdx, 1', 'mov rdi, rax', 'mov eax, 1', 'syscall', 'pop rdi',
                          'push rax', 'mov eax, 3', 'syscall', 'pop rax', 'cmp eax, 1', 'je nopatch',
                          'mov rax, 0xeaadce', 'add rsp, 8', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx',
                          'jmp done', 'nopatch:', 'pop rax', 'pop rdi', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx',
                          'done:']

        assert(self.extract_instrs(generated_patch[1]) == expected_patch)

    def test_x86_64_low_byte_access(self):
        """
        Check that low byte of new x86-64 registers are retrieved correctly from gdb session
        """

        target = bins_dir / "nm-for-low-byte-access-check"
        crash_inp = crash_inps_dir / "nm_low_byte_access_check"
        fuzzer_target_opts = ["-A", "-a", "-l", "-S", "--special-syms", "--synthetic", "-D", "@@"]
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGFPE)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        assert(generated_patch[0] == 0x26f2c3)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "zero_div_reg")
        expected_patch = ['cmp r15b, 0', 'jne label1', 'mov r15b, 218', 'label1:']
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)

    def test_bcmp_patch(self):
        """
        Test if crash at bcmp is patched correctly
        """

        target = bins_dir / "inchi_input_fuzzer"
        crash_inp = crash_inps_dir / "inchi-bcmp-crash"
        fuzzer_target_opts = ["@@"]
        cfg_file = cfgs_dir / "inchi_input_fuzzer.cfg.gz"
        patch_gen = PatchGenerator(target, fuzzer_target_opts)
        ret_val = patch_gen.handle_crash(crash_inp, signal.SIGSEGV)
        assert(ret_val["success"])
        assert(len(ret_val["patches"]) == 1)
        generated_patch = ret_val["patches"][0]
        assert(generated_patch[0] == 0x55c40b)
        patch_type = generated_patch[1].strip().split('\n')[0].split(" = ")[1]
        assert(patch_type == "sigsegv_bcmp")
        expected_patch = ['push rcx', 'push r11', 'push rdx', 'push rsi', 'push rax', 'push rdi', 'push rbx',
                          'push r12', 'push r13', 'mov rbx, rdi', 'mov r12, rsi', 'mov r13, rdx', 'mov rdx, 4095',
                          'not rdx', 'and rdi, rdx', 'lea rsi, [rbx + r13 + 4096]', 'and rsi, rdx', 'sub rsi, rdi',
                          'mov rdx, 0', 'mov rax, 28', 'syscall', 'cmp eax, 0', 'jl skip_memcpy', 'mov rdi, r12',
                          'mov rdx, 4095', 'not rdx', 'and rdi, rdx', 'lea rsi, [r12 + r13 + 4096]', 'and rsi, rdx',
                          'sub rsi, rdi', 'mov rdx, 0', 'mov rax, 28', 'syscall', 'cmp eax, 0', 'jge done',
                          'skip_memcpy:', 'mov rax, 1', 'pop r13', 'pop r12', 'pop rbx', 'pop rdi', 'pop rax', 'pop rsi',
                          'pop rdx', 'pop r11', 'pop rcx', 'jmp 5620752', 'done:', 'pop r13', 'pop r12', 'pop rbx',
                          'pop rdi', 'pop rax', 'pop rsi', 'pop rdx', 'pop r11', 'pop rcx']
        assert(self.extract_instrs(generated_patch[1]) == expected_patch)
        # Apply patches, generate new binary and check if patch was applied correctly
        with gzip.open(cfg_file, 'rb') as fh:
            cfg = pickle.load(fh)

        patched_bin = target.parent / f"{target.name}.patched"
        self.apply_patches([generated_patch], patch_gen.get_injected_bytes_count(), target, patched_bin, cfg)
        # Check disassembly to ensure patch was applied correctly
        proj = angr.Project(patched_bin)
        assert(self.check_block(proj, 0x55c405, ["nop", "jmp 0x6000ffd"]))
        assert(self.check_block(proj, 0x6000ffd, ['movsxd rdx, eax', 'mov rdi, r15', 'push rcx', 'push r11',
                                                  'push rdx', 'push rsi', 'push rax', 'push rdi', 'push rbx', 'push r12',
                                                  'push r13', 'mov rbx, rdi', 'mov r12, rsi', 'mov r13, rdx',
                                                  'mov edx, 0xfff', 'not rdx', 'and rdi, rdx',
                                                  'lea rsi, [rbx + r13 + 0x1000]', 'and rsi, rdx', 'sub rsi, rdi',
                                                  'mov edx, 0', 'mov eax, 0x1c', 'syscall']))
        assert(self.check_block(proj, 0x600103d, ['cmp eax, 0', 'jl 0x600106f']))
        assert(self.check_block(proj, 0x6001042, ['mov rdi, r12', 'mov edx, 0xfff', 'not rdx', 'and rdi, rdx',
                                                  'lea rsi, [r12 + r13 + 0x1000]', 'and rsi, rdx', 'sub rsi, rdi',
                                                  'mov edx, 0', 'mov eax, 0x1c', 'syscall']))
        assert(self.check_block(proj, 0x600106a, ['cmp eax, 0', 'jge 0x6001085']))
        assert(self.check_block(proj, 0x600106f, ["mov eax, 1", "pop r13", "pop r12", "pop rbx", "pop rdi", "pop rax",
                                                  "pop rsi", "pop rdx", "pop r11", "pop rcx", "jmp 0x55c410"]))
        assert(self.check_block(proj, 0x6001085, ["pop r13", "pop r12", "pop rbx", "pop rdi", "pop rax", "pop rsi",
                                                  "pop rdx", "pop r11", "pop rcx", "jmp 0x55c40b"]))
        # Run the patched binary and check it does not crash
        cmd = [patched_bin] + fuzzer_target_opts
        cmd[-1] = crash_inp
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc.wait()
        assert(proc.returncode == 0)
        # Delete patched binary
        patched_bin.unlink()

if __name__ == "__main__":
    unittest.main()
