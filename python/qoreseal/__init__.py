# SPDX-License-Identifier: Apache-2.0
"""ML-KEM-1024 (FIPS 203) encryption of data to QoreChain accounts.

Bindings over the Rust implementation (crates/qoreseal) through UniFFI. The
output is byte-identical to the TypeScript, Rust, Go, Swift and Kotlin
packages; all of them are checked against vectors/qoreseal-v1.json.

Envelopes are sealed with ``seal_envelope`` and opened with ``open_envelope``.
Every failure raises ``QoreSealError.Failure`` with ``code`` (stable across
implementations, for example ``NOT_A_RECIPIENT``) and ``detail``.

Only the payload is confidential: addresses, amounts, timing and sizes stay
public, no zero-knowledge proof is involved, and losing the seed loses access
to the data.
"""

from importlib import metadata as _metadata

from ._ffi import qoreseal_ffi as _ffi
from ._ffi.qoreseal_ffi import *  # noqa: F401,F403

try:
    __version__ = _metadata.version("qorechain-qoreseal")
except _metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "0+unknown"

# Constants of the QoreSeal format, identical across implementations.

#: Algorithm id of ML-KEM-1024 in the chain's KEM key registry and in envelopes.
ALGORITHM_ML_KEM_1024 = 2
#: ML-KEM-1024 sizes in bytes (FIPS 203).
ML_KEM_1024_PUBLIC_KEY_LENGTH = 1568
ML_KEM_1024_SECRET_KEY_LENGTH = 3168
ML_KEM_1024_CIPHERTEXT_LENGTH = 1568
#: Prefix of the text form of an envelope.
ENVELOPE_TEXT_PREFIX = "qoreseal:"
#: Prefix of the HKDF info of every key-encryption key.
KDF_INFO_PREFIX = "qorechain-kem-v1|"
#: Type URLs of the KEM key registry messages.
MSG_REGISTER_KEM_KEY_TYPE_URL = "/qorechain.pqc.v1.MsgRegisterKEMKey"
MSG_REMOVE_KEM_KEY_TYPE_URL = "/qorechain.pqc.v1.MsgRemoveKEMKey"

__all__ = [
    "ALGORITHM_ML_KEM_1024",
    "ML_KEM_1024_PUBLIC_KEY_LENGTH",
    "ML_KEM_1024_SECRET_KEY_LENGTH",
    "ML_KEM_1024_CIPHERTEXT_LENGTH",
    "ENVELOPE_TEXT_PREFIX",
    "KDF_INFO_PREFIX",
    "MSG_REGISTER_KEM_KEY_TYPE_URL",
    "MSG_REMOVE_KEM_KEY_TYPE_URL",
]
__all__ += _ffi.__all__
