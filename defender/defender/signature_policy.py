"""Narrow Authenticode policy used to resolve a measured score collision."""

import io
import logging

from signify.authenticode import AuthenticodeFile


LOGGER = logging.getLogger(__name__)
MICROSOFT_ORGANIZATION = "microsoft corporation"


def has_verified_microsoft_signature(bytez: bytes) -> bool:
    """Return true only for an embedded, trusted Microsoft Authenticode signature.

    Signify validates the file digest, certificate chain, code-signing purpose,
    and timestamp. The leaf publisher must also identify Microsoft Corporation.
    Any parsing or verification failure leaves the malware verdict unchanged.
    """

    try:
        with io.BytesIO(bytez) as stream:
            signed_file = AuthenticodeFile.from_stream(stream)
            verified = signed_file.verify(
                multi_verify_mode="best",
                signature_types="embedded",
            )

            for _signed_data, _indirect_data, chains in verified:
                for chain in chains:
                    if not chain:
                        continue
                    # Signify returns chains in root-to-leaf order.
                    organizations = {
                        value.casefold()
                        for value in chain[-1].subject.get_components("O")
                    }
                    if MICROSOFT_ORGANIZATION in organizations:
                        return True
    except Exception:
        LOGGER.debug("Authenticode verification did not qualify", exc_info=True)

    return False
