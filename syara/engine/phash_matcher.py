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
    Audio perceptual hash implementation for WAV files.

    Uses a dHash-style algorithm on evenly-sampled audio frames:
    reads 65 amplitude values at equal intervals across the file,
    then encodes each consecutive pair comparison as a bit in a 64-bit hash.

    Supports standard uncompressed PCM WAV files via the stdlib ``wave``
    module.  For non-WAV formats or advanced fingerprinting, replace
    ``compute_hash`` with an implementation backed by a dedicated library
    (e.g. chromaprint/acoustid).
    """

    def __init__(self):
        """Initialize AudioHash matcher."""
        self.hash_bits = 64

    def compute_hash(self, file_path: Union[str, Path]) -> int:
        """
        Compute a 64-bit dHash-style fingerprint of a WAV audio file.

        Args:
            file_path: Path to a PCM WAV audio file

        Returns:
            64-bit integer hash

        Raises:
            wave.Error: If the file is not a valid WAV file
            FileNotFoundError: If the file does not exist
        """
        import wave
        import struct

        with wave.open(str(file_path), 'rb') as wav:
            n_frames = wav.getnframes()
            sampwidth = wav.getsampwidth()

            if n_frames == 0:
                return 0

            # Sample 65 evenly-spaced frames to produce a 64-bit dHash
            n_samples = 65
            step = max(1, n_frames // n_samples)

            samples = []
            for i in range(n_samples):
                pos = min(i * step, n_frames - 1)
                wav.setpos(pos)
                raw = wav.readframes(1)
                if not raw:
                    samples.append(0)
                    continue
                # Extract first channel, first sample as a signed integer
                if sampwidth == 1:
                    val = raw[0] - 128          # unsigned 8-bit → signed
                elif sampwidth == 2:
                    val = struct.unpack('<h', raw[:2])[0]
                elif sampwidth == 4:
                    val = struct.unpack('<i', raw[:4])[0]
                else:
                    val = raw[0]
                samples.append(val)

        # Build 64-bit hash: bit i is set when sample[i] > sample[i+1]
        hash_value = 0
        for i in range(64):
            if samples[i] > samples[i + 1]:
                hash_value |= (1 << i)
        return hash_value

    def hamming_distance(self, hash1: int, hash2: int) -> int:
        """Calculate Hamming distance."""
        xor = hash1 ^ hash2
        return bin(xor).count('1')


class VideoHashMatcher(PHashMatcher):
    """
    Video content fingerprint implementation.

    Produces a 64-bit dHash-style fingerprint by sampling 65 raw bytes at
    evenly-spaced offsets across the file and comparing consecutive values.
    This gives a deterministic, reproducible fingerprint that is sensitive to
    content differences without requiring external video-decoding libraries.

    For true perceptual video hashing (frame extraction, visual similarity),
    replace ``compute_hash`` with an implementation backed by a library such
    as OpenCV (``opencv-python``).
    """

    def __init__(self):
        """Initialize VideoHash matcher."""
        self.hash_bits = 64

    def compute_hash(self, file_path: Union[str, Path]) -> int:
        """
        Compute a 64-bit content fingerprint of a video file.

        Reads 65 bytes at evenly-spaced positions across the file and
        encodes each consecutive pair comparison as a bit.

        Args:
            file_path: Path to video file

        Returns:
            64-bit integer fingerprint

        Raises:
            FileNotFoundError: If the file does not exist
        """
        file_path = Path(file_path)
        file_size = file_path.stat().st_size

        if file_size == 0:
            return 0

        n_samples = 65
        samples = []
        with open(file_path, 'rb') as f:
            for i in range(n_samples):
                # Spread samples evenly across [0, file_size - 1]
                pos = int(i * (file_size - 1) / (n_samples - 1)) if file_size > 1 else 0
                f.seek(pos)
                byte = f.read(1)
                samples.append(byte[0] if byte else 0)

        # Build 64-bit hash: bit i is set when sample[i] > sample[i+1]
        hash_value = 0
        for i in range(64):
            if samples[i] > samples[i + 1]:
                hash_value |= (1 << i)
        return hash_value

    def hamming_distance(self, hash1: int, hash2: int) -> int:
        """Calculate Hamming distance."""
        xor = hash1 ^ hash2
        return bin(xor).count('1')
