"""ECDAT backend package.

Modules
-------
``vscode_bridge``        JSON stdin/stdout entrypoint used by the extension.
``scanner``              Safe project traversal and archive extraction.
``detector``             Source-text pattern detection (standard library only).
``openssl_inspector``    X.509 / PEM / DER / PKCS#12 parsing, binary fingerprints.
``container_tools``      Syft and Trivy adapters for container images.
``dependencies``         Manifest parsing for third-party dependency inventory.
``risk``                 Classical rules and Mosca quantum-readiness scoring.
``recommendations``      Remediation text and structured migration guidance.
"""

from .. import SCHEMA_VERSION, __version__

__all__ = ["__version__", "SCHEMA_VERSION"]
