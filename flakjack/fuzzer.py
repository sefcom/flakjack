import pathlib
import shutil
import signal
import subprocess
import time

from typing import List

from phuzzer.phuzzers.afl_plusplus import AFLPlusPlus
import psutil


class Fuzzer(AFLPlusPlus):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._signals_of_interest = [signal.SIGFPE, signal.SIGSEGV]
        self._wait_timeout = 10  # seconds

    def _get_crashing_inputs(self, signals) -> List[pathlib.Path]:
        """
        Override base class function to return path of crashing inputs instead of the crashing inputs themselves
        """

        crash_files = []
        crashes_dir = pathlib.Path(self.work_dir).glob("fuzzer-*/crashes*")
        for crash_dir in crashes_dir:
            if not crash_dir.is_dir():
                # if this entry doesn't have a crashes directory, just skip it
                continue

            for crash in crash_dir.iterdir():
                if crash.name == "README.txt":
                    # skip the readme entry
                    continue

                attrs = dict(map(lambda x: (x[0], x[-1]), map(lambda y: y.split(":"), crash.name.split(","))))

                if int(attrs['sig']) not in signals:
                    continue

                crash_files.append(crash)

        return crash_files

    def add_crashes_to_queue(self) -> None:
        """
        Copy all crashes found, including those not of interest, to queues of all fuzzers for use as seeds in future
        """

        crashes = pathlib.Path(self.work_dir).glob("fuzzer-*/crashes/id*")
        queue_dirs = [x for x in pathlib.Path(self.work_dir).glob("fuzzer-*/queue")]
        for crash in crashes:
            for queue_dir in queue_dirs:
                shutil.copy(crash, queue_dir)

    def add_dictionary(self, dict_file: pathlib.Path) -> None:
        """
        Copy the correctly formatted AFL++ dictionary file to the fuzzer work dir. Dictionary file is not validated.
        """

        shutil.copy(dict_file, self.dictionary_file)

    def find_next_crash(self) -> List[pathlib.Path]:
        """
        Fuzz till a crash of interest is found
        """

        super().start()
        crashes_dir_not_found = 0
        max_crashes_not_found = 10
        no_crashes_found_count = 0
        while True:
            time.sleep(1)
            try:
                crashes = self.crashes(signals=self._signals_of_interest)
                if len(crashes) > 0:
                    for fuzzer_proc in self.processes:
                        fuzzer_proc.terminate()
                        try:
                            fuzzer_proc.wait(self._wait_timeout)
                        except subprocess.TimeoutExpired:
                            fuzzer_proc.kill()

                    return crashes
                else:
                    no_crashes_found_count += 1
                    if no_crashes_found_count > 300:
                        # No crashes found in ~5 mins. Check if at least 1 fuzzer is still alive.
                        for child in psutil.Process().children():
                            if child.name() == "afl-fuzz" and child.status() != "zombie":
                                no_crashes_found_count = 0
                                break
                        else:
                            raise Exception("All fuzzers seem to have exited. Check fuzzer logs to see what happened.")
            except FileNotFoundError as err:
                file_not_found = pathlib.Path(err.filename)
                if file_not_found.name == "crashes" and file_not_found.parent.name.startswith("fuzzer-"):
                    # Sometimes crashes folder is not found; unsure why. Create it and try again upto threshold.
                    file_not_found.mkdir(exist_ok=True)
                    crashes_dir_not_found = crashes_dir_not_found + 1
                    if crashes_dir_not_found > max_crashes_not_found:
                        raise Exception(f"Crashes dir missing in {max_crashes_not_found} trials. Aborting!") from err
                else:
                    raise err
