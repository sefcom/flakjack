import importlib
import pathlib
import signal
import subprocess
import tempfile
import time
from typing import Dict, List, Union

from pwnlib.gdb import Gdb

from rpyc import BgServingThread
from rpyc.core.async_ import AsyncResultTimeout
from rpyc.utils.factory import unix_connect


from .exceptions import GDBSocketNotFoundException
from ..utils import terminate_all_gdb


class GDBWrapper:
    """
    A simple python wrapper around GDB using parts of pwntools
    """

    def __init__(self, target: pathlib.Path, target_args: List[str]):
        self._gdb_proc = None
        self._crash_signal = None
        self._timeout_max_attempts = 5
        with tempfile.TemporaryDirectory(prefix="fj-working-") as tmp_dir:
            working_dir = pathlib.Path(tmp_dir)
            self._out_fh = (working_dir / "tmp-gdb-out").open('w')
            gdb_api_bridge = pathlib.Path(importlib.util.find_spec("pwnlib").origin).parent / "gdb_api_bridge.py"
            gdbinit_file = working_dir / "gdbinit"
            socket_file = working_dir / "socket"
            socket_file.unlink(missing_ok=True)
            with open(gdbinit_file, 'w') as fh:
                fh.write("set confirm off\n")
                fh.write(f"python socket_path = '{socket_file}'\n")
                fh.write(f"source {gdb_api_bridge}")

            cmd = ["gdb", "-x", gdbinit_file, "--args", target] + target_args
            subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=self._out_fh, stderr=self._out_fh)
            for _ in range(5):
                time.sleep(1)
                if socket_file.exists():
                    break
            else:
                raise GDBSocketNotFoundException()

            connection = unix_connect(str(socket_file).encode())
            BgServingThread(connection, callback=lambda : None)
            self._gdb_proc = Gdb(connection)

    def _stop_handler(self, event) -> None:
        """
        gdb stop event callback
        """

        if hasattr(event, "stop_signal"):
            self._crash_signal = event.stop_signal

        return

    def execute(self, gdb_cmd: str) -> Union[str, None]:
        reraise_err = None
        for _ in range(self._timeout_max_attempts):
            try:
                return self._gdb_proc.execute(gdb_cmd, to_string=True)
            except AsyncResultTimeout as err:
                reraise_err = err
                time.sleep(1)

        raise reraise_err

    def get_crash_signum(self) -> Union[signal.Signals, None]:
        try:
            return signal.Signals[self._crash_signal]
        except KeyError:
            return

    def get_fault_addr(self) -> int:
        """
        Get fault address field from siginfo
        """

        resp = self.execute("p $_siginfo._sifields._sigfault.si_addr")
        return int(next(filter(lambda x: x.startswith('0x'), resp.split(' '))), 16)

    def get_func_addr(self, func_name: str) -> int:
        """
        Get address of function
        """

        return int(self.execute(f"info address {func_name}").split(' ')[-1].strip(".\n"), 16)

    def get_stack_frames(self):
        """
        Return all stack frames
        """

        all_frames = []
        for _ in range(self._timeout_max_attempts):
            try:
                curr_frame = self._gdb_proc.newest_frame()
                all_frames.append(curr_frame)
                break
            except AsyncResultTimeout:
                time.sleep(1)
        else:
            # Failed to get frame in multiple attempts. Give up.
            return []

        while True:
            for _ in range(self._timeout_max_attempts):
                try:
                    curr_frame = curr_frame.older()
                    break
                except AsyncResultTimeout:
                    time.sleep(1)
            else:
                # Failed to get next frame in multiple attempts. Give up.
                return []

            if curr_frame:
                all_frames.append(curr_frame)
            else:
                break

        return all_frames

    def get_top_stack_frame(self):
        """
        Return the topmost frame on the stack
        """

        return self._gdb_proc.newest_frame()

    def get_mem_mapping(self) -> Union[List[Dict[str, Union[int, str]]], None]:
        """
        Get memory mapping
        """

        resp = self.execute("info proc mappings")
        entries = [x.strip() for x in resp.split('\n') if x != '']
        for c, i in enumerate(entries):
            if i.startswith("Start Addr"):
                first_entry = c + 1
                break
        else:
            # Failed to find header row in mapping output
            return

        mappings = []
        for entry in entries[first_entry:]:
            data = [x for x in entry.split(' ') if x != '']
            if len(data) == 5:
                data.append('')

            start, end, size, offset, perms, image = data
            perm_int = 0
            if 'r' in perms:
                perm_int |= 4

            if 'w' in perms:
                perm_int |= 2

            if 'x' in perms:
                perm_int |= 1

            mappings.append({"start": int(start, 16), "end": int(end, 16), "size": int(size, 16),
                             "offset": int(offset, 16), "perms": perm_int, "image": image})

        return mappings

    def get_mem_value(self, mem_addr: int, size: int) -> int:
        """
        Read value size bytes long at mem_addr
        """

        size_letter_map = {1: 'b', 2: 'h', 4: 'w', 8: 'g'}
        resp = self.execute(f"x/u{size_letter_map[size]} {mem_addr}")
        return int(resp.split('\t')[1])

    def get_reg_value(self, reg_name: str) -> int:
        """
        Get value of register
        """

        # GDB uses prefix l instead of b to access lowest byte of r8 - r15
        reg_name_fixes = {"r8b": "r8l", "r9b": "r9l", "r10b": "r10l", "r11b": "r11l", "r12b": "r12l", "r13b": "r13l",
                          "r14b": "r14l", "r15b": "r15l"}
        if reg_name in reg_name_fixes:
            reg_name = reg_name_fixes[reg_name]

        resp = self.execute(f"p/u ${reg_name}")
        return int(resp.split('=')[1])

    def run_till_crash(self, timeout: int) -> bool:
        self._gdb_proc.events.stop.connect(self._stop_handler)
        self.execute("run")
        poll_interval = 5  # seconds
        ret_val = False
        for _ in range(int(timeout / poll_interval)):
            time.sleep(poll_interval)
            curr_threads = self._gdb_proc.selected_inferior().threads()
            if curr_threads:
                if curr_threads[0].is_stopped() and self._crash_signal is not None:
                    ret_val = True
                    break

        self._gdb_proc.events.stop.disconnect(self._stop_handler)
        return ret_val

    def stop(self) -> None:
        if not self._out_fh.closed:
            self._out_fh.close()

        if not self._gdb_proc.conn.closed:
            for _ in range(self._timeout_max_attempts):
                try:
                    self._gdb_proc.quit()
                    return
                except AsyncResultTimeout:
                    time.sleep(1)

            # Failed to quit gdb via python API. Attempt to do so using psutil
            terminate_all_gdb()
