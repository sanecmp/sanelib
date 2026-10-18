# Shared protocol development guide

sanelib contains the validated wire models shared by sanea and sanex. It has no standalone service or command-line interface.

Its Python distribution is `sanecmp-sanelib`; the import package remains `sanelib`.

## Requirements

Python 3.12+. Runtime dependencies are installed with the package.
Local development uses uv and makeapp (`makeapp>=2.3,<3`).

## Installation

sanea and sanex install this library as a dependency.
It has no standalone service or command-line interface.

## Local development

Run these commands from the `sanelib/` package directory:

```bash
ma tools
ma tests
```

`ma tools` prepares development tools, and `ma tests` runs the configured Python 3.12
test matrix. CI continues to run pytest directly, without makeapp.
The samples in `tests/sanelib/protocol/datafixtures/` are synthetic protocol data,
not collected user events or real certificates.

## Release builds

Build wheel and sdist files with:

```bash
uv build
```

## Application identities

A process-start event may include `application` with a namespaced `ident` and
display `name`. Raw `prc_name` and `exe` remain unchanged. The ID is not a process
or launch identifier. Unknown applications have no semantic identity.

An application rule may use `app_id` as an exact recognition condition. It is
combined with any process-name, executable and window-title conditions using AND.
The rule's parent-facing `name` remains a label, not a condition.
