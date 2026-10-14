"""ECDAT backend namespace.

``backend`` is the canonical engine source of truth for the Periperi VS Code
extension. The sources live at ``engine/backend`` inside the extension, and
``scripts/prepare-engine.mjs`` bundles the per-platform Python runtime under
``engine/runtime`` without modifying these files.
"""

__version__ = "0.4.0"

#: Schema identifier written into every bridge response and CBOM export.
SCHEMA_VERSION = "ECDAT CBOM Prototype 1.2"

__all__ = ["__version__", "SCHEMA_VERSION"]
