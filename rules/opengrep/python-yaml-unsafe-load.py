# Annotated test file for python-yaml-unsafe-load. Deliberately vulnerable: do not run.
import yaml


def read_unsafe(stream):
    # ruleid: python-yaml-unsafe-load
    return yaml.load(stream, Loader=yaml.Loader)


def read_full(stream):
    # ruleid: python-yaml-unsafe-load
    return yaml.load(stream, yaml.FullLoader)


def read_explicit(stream):
    # ruleid: python-yaml-unsafe-load
    return yaml.unsafe_load(stream)


def read_safe(stream):
    # ok: python-yaml-unsafe-load
    return yaml.safe_load(stream)


def read_safe_loader(stream):
    # ok: python-yaml-unsafe-load
    return yaml.load(stream, Loader=yaml.SafeLoader)
