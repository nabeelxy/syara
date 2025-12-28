"""
Perceptual hash matching for binary files (images, audio, video).

This module provides abstract base class for phash matchers and reference implementations.
PHash is used for detecting near-duplicate or similar binary content.
"""
from abc import ABC, abstractmethod
from typing import Union
from pathlib import Path


class PHashMatcher(ABC):
    """Abstract base class for perceptual hash matchers."""

    @abstractmethod
    def compute_hash(self, file_path: Union[str, Path]) -> int:
        """
        Compute perceptual hash of a file.

        Args:
            file_path: Path to binary file (image, audio, or video)

        Returns:
            Integer hash value
        """
        pass

    @abstractmethod
    def hamming_distance(self, hash1: int, hash2: int) -> int:
        """
        Calculate Hamming distance between two hashes.

        Args:
            hash1: First hash
            hash2: Second hash

        Returns:
            Number of differing bits
        """
        pass

    def normalized_distance(self, hash1: int, hash2: int, bits: int = 64) -> float:
        """
        Calculate normalized Hamming distance (0.0 to 1.0).

        Args:
            hash1: First hash
            hash2: Second hash
            bits: Number of bits in hash (default 64)

        Returns:
            Normalized distance between 0.0 and 1.0
        """
        distance = self.hamming_distance(hash1, hash2)
        return distance / bits

    def similarity(self, file1: Union[str, Path], file2: Union[str, Path], bits: int = 64) -> float:
        """
        Calculate similarity between two files using phash.

        Args:
            file1: Path to first file
            file2: Path to second file
            bits: Number of bits in hash

        Returns:
            Similarity score between 0.0 (different) and 1.0 (identical)
        """
        hash1 = self.compute_hash(file1)
        hash2 = self.compute_hash(file2)
        distance = self.normalized_distance(hash1, hash2, bits)
        return 1.0 - distance  # Convert distance to similarity


class ImageHashMatcher(PHashMatcher):
    """
    Image perceptual hash implementation.

    Uses difference hash (dHash) algorithm for image comparison.
    This is a simple but effective algorithm for detecting near-duplicate images.

    Note: For production use, consider using the 'imagehash' library which provides
    multiple algorithms (aHash, pHash, dHash, wHash).
    """

    def __init__(self, hash_size: int = 8):
        """
        Initialize ImageHash matcher.

        Args:
            hash_size: Size of hash grid (default: 8, resulting in 64-bit hash)
        """
        self.hash_size = hash_size
        self.hash_bits = hash_size * hash_size

    def compute_hash(self, file_path: Union[str, Path]) -> int:
        """
        Compute perceptual hash of an image file.

        This is a simplified implementation. For production use, install the
        'imagehash' library and use their implementations.

        Args:
            file_path: Path to image file

        Returns:
            64-bit integer hash

        Raises:
            ImportError: If PIL (Pillow) is not installed
            FileNotFoundError: If image file doesn't exist
        """
        try:
            from PIL import Image
        except ImportError:
            raise ImportError(
                "PIL (Pillow) is required for image hashing. "
                "Install it with: pip install Pillow"
            )

        # Load and preprocess image
        img = Image.open(file_path).convert('L')  # Convert to grayscale
        img = img.resize((self.hash_size + 1, self.hash_size), Image.Resampling.LANCZOS)

        # Compute difference hash
        pixels = list(img.getdata())

        # Calculate horizontal gradient
        hash_value = 0
        for row in range(self.hash_size):
            for col in range(self.hash_size):
                pixel_left = pixels[row * (self.hash_size + 1) + col]
                pixel_right = pixels[row * (self.hash_size + 1) + col + 1]

                # Set bit if left pixel is brighter than right
                if pixel_left > pixel_right:
                    hash_value |= (1 << (row * self.hash_size + col))

        return hash_value

    def hamming_distance(self, hash1: int, hash2: int) -> int:
        """
        Calculate Hamming distance between two hashes.

        Args:
            hash1: First hash
            hash2: Second hash

        Returns:
            Number of differing bits
        """
        xor = hash1 ^ hash2
        distance = 0
        while xor:
            distance += xor & 1
            xor >>= 1
        return distance


class AudioHashMatcher(PHashMatcher):
    """
    Audio perceptual hash implementation.

    This is a placeholder implementation. For production use, consider libraries like:
    - chromaprint/acoustid for audio fingerprinting
    - dejavu for audio recognition
    """

    def __init__(self):
        """Initialize AudioHash matcher."""
        self.hash_bits = 64

    def compute_hash(self, file_path: Union[str, Path]) -> int:
        """
        Compute perceptual hash of an audio file.

        This is a placeholder. Implement using audio fingerprinting libraries.

        Args:
            file_path: Path to audio file

        Returns:
            Hash value

        Raises:
            NotImplementedError: This is a placeholder implementation
        """
        raise NotImplementedError(
            "AudioHashMatcher is a placeholder. For production use, install and use "
            "a library like 'pyacoustid' or implement custom audio fingerprinting."
        )

    def hamming_distance(self, hash1: int, hash2: int) -> int:
        """Calculate Hamming distance."""
        xor = hash1 ^ hash2
        return bin(xor).count('1')


class VideoHashMatcher(PHashMatcher):
    """
    Video perceptual hash implementation.

    This is a placeholder implementation. Video hashing typically involves:
    - Extracting key frames
    - Computing image hashes for each frame
    - Aggregating frame hashes
    """

    def __init__(self):
        """Initialize VideoHash matcher."""
        self.hash_bits = 64

    def compute_hash(self, file_path: Union[str, Path]) -> int:
        """
        Compute perceptual hash of a video file.

        This is a placeholder. Implement using video processing libraries.

        Args:
            file_path: Path to video file

        Returns:
            Hash value

        Raises:
            NotImplementedError: This is a placeholder implementation
        """
        raise NotImplementedError(
            "VideoHashMatcher is a placeholder. For production use, implement using "
            "libraries like 'opencv-python' to extract frames and hash them."
        )

    def hamming_distance(self, hash1: int, hash2: int) -> int:
        """Calculate Hamming distance."""
        xor = hash1 ^ hash2
        return bin(xor).count('1')
