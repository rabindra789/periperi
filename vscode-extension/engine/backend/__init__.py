"""ECDAT backend namespace.

``backend`` is the engine source of truth for the Periperi 0.3.0 VS Code
extension. ``vscode-extension/scripts/prepare-engine.mjs`` copies this package
into ``vscode-extension/engine/`` and bundles the platform Python runtimes, so
edit the files here rather than the vendored copy.
"""

__version__ = "0.3.0"

#: Schema identifier written into every bridge response and CBOM export.
SCHEMA_VERSION = "ECDAT CBOM Prototype 1.1"

__all__ = ["__version__", "SCHEMA_VERSION"]
