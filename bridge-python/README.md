# atibon-core

Python bindings for the native ATIBON defensive firewall core.

## Installation

From this directory:

```bash
python -m pip install .
```

Build a wheel with:

```bash
python -m pip install -U maturin
maturin build --release --out dist
```

Then install the generated wheel with `python -m pip install dist/<wheel>.whl`.
