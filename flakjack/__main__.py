#!/usr/bin/env python3


import argparse
import pathlib
import pickle


from .project import Project


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Command line arguments parser
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", type=str, required=True, help="Path to the target to be analyzed")
    parser.add_argument("-to", "--target-opts", type=str, required=True, nargs="+",
                        help="Options for fuzzing the target(use ~ instead of -)")
    parser.add_argument("-sd", "--seeds-dir", type=str, required=True, help="Directory with initial seeds for fuzzer")
    parser.add_argument("-wd", "--work-dir", type=str, required=True, help="Out folder for results")
    # Optional arguments
    parser.add_argument("-r", "--runners", type=int, required=False, default=2, help="Number of fuzzer instances to run")
    parser.add_argument("-m", "--memory", type=str, required=False, default="8G",
                        help="Memory to allocate per experiment(use K, M, G prefixes)")
    parser.add_argument("--cfg", type=str, required=False, help="File with pickle'd CFG")
    parser.add_argument("-ci", "--crash-input", type=str, required=False, help="First crashing input to start with (named similar as AFL++ output)")
    parser.add_argument("-df", "--dict-file", type=str, required=False, help="Dictionary file")
    return parser


def main():
    args = create_argument_parser().parse_args()
    target = pathlib.Path(args.target).resolve()
    seeds_dir = pathlib.Path(args.seeds_dir).resolve()
    work_dir = pathlib.Path(args.work_dir).resolve()
    runners = args.runners
    memory = args.memory
    cfg = None
    crash_input = None
    dictionary_file = None

    if not target.is_file():
        print(f"{target} is not a valid file")
        return

    if not seeds_dir.is_dir():
        print(f"{seeds_dir} is not a valid directory")
        return

    target_opts = []
    for opt in args.target_opts:
        if opt.startswith("~~"):
            target_opts.append("--" + opt[2:])
        elif opt.startswith("~"):
            target_opts.append("-" + opt[1:])
        else:
            target_opts.append(opt)

    if args.cfg:
        cfg_file = pathlib.Path(args.cfg).resolve()
        if cfg_file.is_file():
            with cfg_file.open("rb") as fh:
                cfg = pickle.load(fh)
        else:
            print(f"{str(cfg_file)} is not a valid file. Ignoring.")

    if args.crash_input:
        crash_input = pathlib.Path(args.crash_input).resolve()
        if not crash_input.is_file():
            print(f"{str(crash_input)} is not a valid file. Ignoring")
            crash_input = None

    if args.dict_file:
        dictionary_file = pathlib.Path(args.dict_file).resolve()
        if not dictionary_file.is_file():
            print(f"{str(dictionary_file)} is not a valid file. Ignoring")
            dictionary_file = None

    project = Project(target, target_opts, seeds_dir, work_dir, runners, memory, cfg, crash_input, dictionary_file)
    project.run()
    return


if __name__ == "__main__":
    main()
