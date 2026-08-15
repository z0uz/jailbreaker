"""
Data Augmentation module for input normalization shifts, noise injection, and filtering stress tests.
"""

import re
import unicodedata
import random
from typing import List, Dict, Callable

class InputAugmenter:
    """Provides data augmentation transformations for testing robustness under input variations."""
    
    @staticmethod
    def normalize_unicode(text: str, form: str = "NFD") -> str:
        """Apply Unicode normalization (NFC, NFD, NFKC, NFKD)."""
        return unicodedata.normalize(form, text)

    @staticmethod
    def whitespace_shift(text: str) -> str:
        """Modify whitespace patterns (tabs, multiple spaces, trailing spaces)."""
        lines = text.splitlines()
        augmented = []
        for line in lines:
            if line.startswith("    "):
                augmented.append("\t" + line[4:])
            else:
                augmented.append(line + "  ")
        return "\n".join(augmented)

    @staticmethod
    def inject_noise(text: str, rate: float = 0.05) -> str:
        """Inject subtle non-breaking or zero-width character noise."""
        result = []
        for char in text:
            result.append(char)
            if char in (' ', '\n', ';', '=') and random.random() < rate:
                result.append('\u200b')  # Zero-width space
        return "".join(result)

    @staticmethod
    def case_shift(text: str) -> str:
        """Apply case transformations where appropriate."""
        return text.swapcase()

    @staticmethod
    def html_encode(text: str) -> str:
        """Simulate HTML entity encoding filtering."""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    @classmethod
    def get_all_augmentations(cls) -> Dict[str, Callable[[str], str]]:
        """Return dict of available transformation functions."""
        return {
            "unicode_nfd": lambda s: cls.normalize_unicode(s, "NFD"),
            "whitespace_shift": cls.whitespace_shift,
            "zero_width_noise": cls.inject_noise,
            "html_encode": cls.html_encode
        }

    @classmethod
    def apply_augmentations(cls, text: str) -> Dict[str, str]:
        """Apply all available transformations and return dictionary of augmented variants."""
        results = {"original": text}
        for name, func in cls.get_all_augmentations().items():
            try:
                results[name] = func(text)
            except Exception:
                results[name] = text
        return results
