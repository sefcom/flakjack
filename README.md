# README

This repository consists source code of FlakJack, an implementation of Robust Fuzzing technique to
discover Occluded Future Vulnerabilities. For more details about Robust Fuzzing and Occluded Future
Vulnerabilities, refer to [our paper](https://sefcom.asu.edu/publications/flakjack-ccs24.pdf).

## Installation

The easiest way to run FlakJack is to use the pre-built Docker image:

```bash
docker pull ghcr.io/sefcom/flakjack:public
```

Alternatively, build a Docker image using repo:

```bash
docker build -t flakjack .
```

## Running FlakJack

FlakJack can be run from command line directly. Run `python -m flakjack` to view usage. FlakJack can
also be run as a library. See [`__main__.py`](flakjack/__main__.py) for an example usage as library.

## Running experiments

See [experiments.md](docs/experiments.md) for more instructions on how to run the experiments we performed in the paper.

## Citing

If you use FlakJack, we would be grateful if you could cite our work use the following BibTeX entry:

```bibtex
@inproceedings{flakjack,
  author = {Arvind S Raj and Wil Gibbs and Fangzhou Dong and Jayakrishna Menon Vadayath and Michael Tompkins and
            Steven Wirsz and Yibo Liu and Zhenghao Hu and Chang Zhu and Gokulkrishna Praveen Menon and
            Brendan Dolan-Gavitt and Adam Doup{\'e} and Ruoyu Wang and Yan Shoshitaishvili and Tiffany Bao},
  title = {\emph{Fuzz to the Future:} {Uncovering Occluded Future Vulnerabilities via Robust Fuzzing}},
  booktitle = {Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security (CCS '24)},
  year = {2024}
}
```
