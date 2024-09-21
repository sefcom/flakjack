import io
import json
import logging
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import List, Tuple, Union

from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import AddRWDataPatch, InsertCodePatch

from rpyc.core.async_ import AsyncResultTimeout

from .fuzzer import Fuzzer
from .patch_generator import PatchGenerator
from .utils import terminate_all_gdb


logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)


class Project:
    """
    The main class that drives entire analysis process
    """

    def __init__(self, target: pathlib.Path, target_opts: List[str], seeds_dir: pathlib.Path, work_dir: pathlib.Path,
                 runner_count: int, memory: str, cfg=None, crash_inp: pathlib.Path=None, dict_file: pathlib.Path=None):
        """
        :param target: Path to target
        :param target_opts: Command line options for target
        :param seeds_dir: Directory with initial seeds
        :param work_dir: Output directory
        :param runner_count: Number of fuzzer instances to run
        :praam memory: Total memory to use across all fuzzer instances
        :param cfg: The CFG of target generated using angr
        :param crash_inp: The first crashing input to start with
        :param dict_file: Dictionary file for fuzzer
        """

        self.target = target
        self.target_opts = target_opts
        self.seeds = []
        self.work_dir = work_dir
        self.runner_count = runner_count
        self._dict_file = None
        self._cfg = cfg
        self._per_runner_mem = str(int(int(memory[:-1]) / runner_count)) + memory[-1]
        self._fuzzer_work_dir: pathlib.Path = self.work_dir / "fuzzer"
        self._saved_data_dir = self.work_dir / "saved_data"
        self._first_crash_input = None
        self._processed_first_crash = False
        if crash_inp:
            if not crash_inp.is_file():
                logger.warning("%s is not a valid file. Not using as first crashing input", str(crash_inp))
            else:
                try:
                    _ = int(crash_inp.name.split(',')[1].split(':')[1])
                    self._first_crash_input = crash_inp
                    with self._first_crash_input.open('rb') as fh:
                        self.seeds.append(fh.read())
                except:
                    logger.warning("Failed to retrieve signal info from file name of first crashing input. Ignoring.")

        if self.work_dir.is_dir():
            shutil.rmtree(str(self.work_dir))

        self._saved_data_dir.mkdir(parents=True)

        for afile in seeds_dir.glob("**/*"):
            if afile.is_file():
                with afile.open('rb') as seedfile:
                    self.seeds.append(seedfile.read())

        if dict_file:
            if not dict_file.is_file():
                logger.warning("%s is not a valid file. Not using as dictionary", str(dict_file))
            else:
                self._dict_file = dict_file

    def _apply_patches(self, patches: Tuple[int, str], data_size: int, orig_bin: pathlib.Path, patched_bin: pathlib.Path, prev_bin: pathlib.Path) -> Union[Tuple[int, int], None]:
        logger.info("Applying patches using patcherex")
        max_attempts = 5
        for curr_attempt in range(1, max_attempts + 1):
            logger.info("Patch attempt %d/%d", curr_attempt, max_attempts)
            patch_objs = []
            for addr, patch_asm in patches:
                patch_objs.append(InsertCodePatch(addr, patch_asm))

            if data_size != 0:
                patch_objs.append(AddRWDataPatch(data_size))

            backend = DetourBackend(str(orig_bin), cfg=self._cfg)
            status = backend.apply_patches(patch_objs)
            if not status:
                logger.warning("patcherex could not apply patch. Not trying again.")
                return False

            # Apply patch and compare disassembly with previous version to ensure patch was applied
            logger.info("Applied all patches in patcherex.")
            backend.save(str(patched_bin))
            with tempfile.TemporaryDirectory() as adir:
                work_dir = pathlib.Path(adir).resolve()
                shutil.copy(patched_bin, work_dir / orig_bin.name)
                curr_disassembly_file = work_dir / f"{patched_bin.name}.dis"
                cmd = f"objdump -M intel -d {work_dir / orig_bin.name} >{curr_disassembly_file} 2>/dev/null"
                os.system(cmd)
                shutil.copy(prev_bin, work_dir / orig_bin.name)
                prev_disassembly_file = work_dir / f"{prev_bin.name}.dis"
                cmd = f"objdump -M intel -d {work_dir / orig_bin.name} > {prev_disassembly_file} 2>/dev/null"
                os.system(cmd)
                compare_cmd = ["diff", prev_disassembly_file, curr_disassembly_file]
                proc = subprocess.Popen(compare_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.wait()
                if proc.returncode == 1:
                    # Disassembly differ => patch was applied and saved to disk correctly. We're done.
                    logger.info("Saved all patches to disk correctly")
                    out, _ = proc.communicate()
                    for aline in io.BytesIO(out):
                        if aline.startswith(b"> ") and b"jmp" in aline:
                            patch_start = int(aline.split(b'\t')[-1].split(b' ')[-2], 16)
                            patch_detour_loc = int(aline.split(b':')[0].split(b' ')[-1], 16)
                            return (patch_detour_loc, patch_start)
                    else:
                        logger.warning("Patching suceeded but failed to find detour to patch in patched binary")
                else:
                    logger.warning("Saving patches to disk failed for some reason")
        else:
            # Patch was not written out correctly in max attempts. Give up.
            logger.warning("Failed to patch in %d attempts. Giving up.", max_attempts)
            return

    def run(self):
        curr_target = self.target
        patches = []
        fuzzer_run_count = 0
        max_patching_attempts = 5
        patch_generator = PatchGenerator(curr_target, self.target_opts)
        project_run_dir = pathlib.Path.home() / "project"
        project_run_dir.mkdir(exist_ok=True)
        os.chdir(project_run_dir)
        while True:
            if self._first_crash_input and not self._processed_first_crash:
                logger.info("Processing provided initial crashing input")
                crashes = [self._first_crash_input]
            else:
                # Find a crash using fuzzer
                fuzzer_run_count += 1
                logger.info("Starting fuzzer run %d", fuzzer_run_count)
                fuzzer = Fuzzer(target=str(curr_target), target_opts=self.target_opts, seeds=self.seeds,
                                work_dir=str(self._fuzzer_work_dir), afl_count=self.runner_count, memory=self._per_runner_mem,
                                timeout=None, use_qemu=False, resume=(fuzzer_run_count > 0), create_dictionary=False)
                if self._dict_file:
                    fuzzer.add_dictionary(self._dict_file)

                crashes = fuzzer.find_next_crash()
                logger.info("Fuzzer found %d crashes", len(crashes))
                # Add all crashes to queue of all fuzzers
                fuzzer.add_crashes_to_queue()

            # Time to patch the crash found
            data_save_dir = self._saved_data_dir / str(fuzzer_run_count)
            asm_patches_dir = data_save_dir / "asm-patches"
            success_asm_patches_dir = asm_patches_dir / "success"
            failed_asm_patches_dir = asm_patches_dir  / "failed"
            crashes_dir = data_save_dir / "crashes"
            patched_crashes_dir = crashes_dir / "patched"
            unpatched_crashes_dir = crashes_dir / "unpatched"
            success_asm_patches_dir.mkdir(parents=True)
            failed_asm_patches_dir.mkdir(parents=True)
            patched_crashes_dir.mkdir(parents=True)
            unpatched_crashes_dir.mkdir(parents=True)
            patched_json_data = []
            unpatched_json_data = []
            # Attempt to generate a patch for all crashes found till one succeeds.
            logger.info("Running patch generator")
            for crash_count, crash in enumerate(crashes, start=1):
                crash_signum = int(crash.name.split(',')[1].split(':')[1])
                for _ in range(max_patching_attempts):
                    try:
                        ret_val = patch_generator.handle_crash(crash, crash_signum)
                        break
                    except AsyncResultTimeout:
                        ret_val = {"success": False, "reason": "Timeout from GDB API"}
                        terminate_all_gdb()

                os.chdir(project_run_dir)
                if ret_val["success"]:
                    # Patch generated. Attempt applying patch.
                    curr_patches = ret_val["patches"]
                    patched_bin_path = data_save_dir / f"{fuzzer_run_count}_{self.target.name}"
                    status = self._apply_patches(patches + curr_patches, patch_generator.get_injected_bytes_count(),
                                                self.target, patched_bin_path, curr_target)
                    # Save the patch assembly code, crashing input, mapping between crash file and patch file and patch
                    # application status
                    patch_details = []
                    for curr_patch_count, curr_patch in enumerate(curr_patches, start=1):
                        patch_file_name = f"{fuzzer_run_count}-{crash_count}-{curr_patch_count}.patch"
                        patch_detail = {"patch_file": patch_file_name, "patch_insert_addr": hex(curr_patch[0])}
                        if status:
                            patch_file = success_asm_patches_dir / patch_file_name
                            patch_detour_loc, patch_loc = status
                            patch_detail["patch_detour_addr"] = patch_detour_loc
                            patch_detail["patch_start_addr"] = patch_loc
                        else:
                            patch_file = failed_asm_patches_dir / patch_file_name

                        logger.info("Saving patch %d to %s", curr_patch_count, patch_file.relative_to(asm_patches_dir))
                        with patch_file.open('w') as fh:
                            fh.write(curr_patch[1])

                        patch_details.append(patch_detail)

                    if status:
                        # Mark crash as patched, save new patches and update target
                        shutil.move(crash, patched_crashes_dir)
                        patched_json_data.append({"crash_file": crash.name, "target": curr_target.name,
                                                  "patches": patch_details})
                        patches.extend(curr_patches)
                        curr_target = patched_bin_path
                        patch_generator.update_target(curr_target)
                        break
                    else:
                        shutil.move(crash, unpatched_crashes_dir)
                        unpatched_json_data.append({"crash_file": crash.name, "target": curr_target.name,
                                                    "patches": patch_details, "reason": "patcherex failure"})
                else:
                    # Triager failed to create patch. Save crash file and reason why patch could not be generated
                    logger.info("Failed to generate patch.")
                    shutil.move(crash, unpatched_crashes_dir)
                    save_data = {"crash_file": crash.name, "target": curr_target.name, "reason": ret_val["reason"]}
                    if "instr" in ret_val:
                        save_data["instr"] = ret_val["instr"]

                    unpatched_json_data.append(save_data)

            # Save data about triager status
            if patched_json_data:
                with (patched_crashes_dir / "info.json").open('w') as fh:
                    json.dump(patched_json_data, fh, indent=4)

            if unpatched_json_data:
                with (unpatched_crashes_dir / "info.json").open('w') as fh:
                    json.dump(unpatched_json_data, fh, indent=4)

            # Save crashing inputs not processed by triager if any
            unprocessed_crashes_dir = crashes_dir / "unprocessed"
            unprocessed_crashes_dir.mkdir(parents=True)
            logger.info("Saving unprocessed crashes to %s", unprocessed_crashes_dir)
            for adir in pathlib.Path(self._fuzzer_work_dir).glob("fuzzer-*"):
                src_dir = adir / "crashes"
                if src_dir.is_dir() and any(src_dir.iterdir()):
                    # Save crashes directory only if not empty
                    dest_dir = unprocessed_crashes_dir / adir.name
                    shutil.move(src_dir, dest_dir)
                    src_dir.mkdir()

            if self._first_crash_input and not self._processed_first_crash and curr_target == self.target:
                # Failed to patch first crashing input provided => stop
                logger.warning("Failed to patch crashing input providing. Exiting!")
                break

            # Mark first input as processed, if provided
            self._processed_first_crash = True
