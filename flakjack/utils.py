import psutil


def terminate_all_gdb():
    # Attempt to terminate all running gdb. If any exception occurs, silently ignore.
    gdb_procs = []
    try:
        for child in psutil.Process().children(recursive=True):
            if child.status() == "zombie" or child.name() == "gdb":
                gdb_procs.append(child)
                child.terminate()

        _, alive = psutil.wait_procs(gdb_procs, timeout=1)
        if alive:
            for proc in alive:
                proc.kill()
    except:
        pass
