# sanelib

sanelib contains the validated wire models shared by sanea and sanex. It has no standalone service or command-line interface.

Its Python distribution is `sanecmp-sanelib`; the import package remains `sanelib`.

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
