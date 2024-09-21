from distutils.core import setup

setup(
    name="flakjack",
    version="0.1",
    description="flakjack",
    install_requires=[
        "patcherex",
        "phuzzer",
        # Pin ROPgadget to version that works with capstone version angr needs
        "ROPgadget==7.3",
        "pwntools==4.11.0",
        "psutil",
    ]
)
