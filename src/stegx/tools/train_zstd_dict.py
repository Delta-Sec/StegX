from __future__ import annotations

import sys
from pathlib import Path
from typing import List

_DEFAULT_DICT_BYTES = 8 * 1024

def _pe_samples() -> List[bytes]:
    samples = []
    for i in range(12):

        mz = b"MZ" + bytes(58) + (0x80 + i * 4).to_bytes(4, "little")
        dos_stub = (
            b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
            b"This program cannot be run in DOS mode.\r\r\n$"
        )
        pe = (
            b"PE\0\0"
            + b"\x4c\x01"
            + (3 + i).to_bytes(2, "little")
            + b"\x00\x00\x00\x00" * 3
            + b"\xe0\x00"
            + b"\x02\x01"
        )
        samples.append(mz + dos_stub + pe + b"\x00" * 120)
    return samples

def _elf_samples() -> List[bytes]:
    samples = []
    for i in range(12):
        header = (
            b"\x7fELF"
            + b"\x02"
            + b"\x01"
            + b"\x01"
            + b"\x00"
            + bytes(8)
            + (2 + (i % 3)).to_bytes(2, "little")
            + b"\x3e\x00"
            + b"\x01\x00\x00\x00"
        )
        program_hdr = (
            b"\x06\x00\x00\x00"
            + b"\x04\x00\x00\x00"
            + b"\x40\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00" * 40
        )
        samples.append(header + program_hdr + b"\x00" * 128)
    return samples

def _pdf_samples() -> List[bytes]:
    samples = []
    for i in range(10):
        body = (
            b"%PDF-1.7\n"
            b"%\xe2\xe3\xcf\xd3\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents " + str(4 + i).encode() + b" 0 R >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f\n"
            b"0000000010 00000 n\n0000000060 00000 n\n0000000120 00000 n\n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%EOF\n" % (200 + i)
        )
        samples.append(body)
    return samples

def _zip_samples() -> List[bytes]:
    samples = []
    for i in range(10):
        local = (
            b"PK\x03\x04"
            + b"\x14\x00\x00\x00\x08\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x08\x00\x00\x00"
            + (f"file{i:04d}.bin").encode()[:8]
            + b"\x00" * 80
        )
        eocd = (
            b"PK\x05\x06"
            + b"\x00\x00\x00\x00"
            + b"\x01\x00\x01\x00"
            + b"\x48\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00"
        )
        samples.append(local + eocd)
    return samples

def _json_samples() -> List[bytes]:
    samples = []
    for i in range(20):
        samples.append(
            (
                b'{"version":"1.0","name":"sample","items":['
                b'{"id":%d,"value":"hello"}]}' % (i + 1)
            )
        )
        samples.append(
            b'{"status":"ok","timestamp":"2026-04-%02dT12:00:00Z","payload":{}}'
            % ((i % 28) + 1)
        )
        samples.append(
            b'{"user":"alice","role":"admin","permissions":["read","write","delete"]}'
        )
        samples.append(
            b'{"type":"record","fields":[{"name":"id","type":"int"},'
            b'{"name":"label","type":"string"}]}'
        )
    return samples

def _text_samples() -> List[bytes]:
    samples = []
    for i in range(8):
        samples.append(
            (b"The quick brown fox jumps over the lazy dog. " * 4)
            + (b"StegX payload sample %d " % i) * 3
        )
        samples.append(
            b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
            b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n"
        )
    return samples

def _image_samples() -> List[bytes]:


    samples = [
        b"\x89PNG\r\n\x1a\n" + bytes(40),
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00\x00\x02\x00\x00\x00\x02\x00"
        + b"\x08\x02\x00\x00\x00" + bytes(20),
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x48\x00\x48\x00\x00",
        b"\xff\xd8\xff\xe1" + bytes(100) + b"Exif\x00\x00",
        b"GIF89a\x00\x00\x00\x00\x80\x00\x00",
        b"BM\x46\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00",
    ]
    return [s + bytes((i * 7) & 0xff for i in range(64)) for s in samples]

def build_corpus() -> List[bytes]:
    return (
        _pe_samples()
        + _elf_samples()
        + _pdf_samples()
        + _zip_samples()
        + _json_samples()
        + _text_samples()
        + _image_samples()
    )

def train(target_size_bytes: int = _DEFAULT_DICT_BYTES) -> bytes:
    import zstandard

    corpus = build_corpus()
    if len(corpus) < 8:
        raise RuntimeError("Corpus too small to train a zstd dictionary.")
    zdict = zstandard.train_dictionary(target_size_bytes, corpus, threads=0)
    return zdict.as_bytes()

def default_output_path() -> Path:
    here = Path(__file__).resolve().parent.parent
    return here / "data" / "stegx_dict_v1.zstd"

def main(argv: List[str]) -> int:
    target = _DEFAULT_DICT_BYTES if len(argv) < 2 else int(argv[1])
    out = default_output_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    blob = train(target)
    out.write_bytes(blob)
    print(f"Wrote {len(blob)} bytes of zstd dictionary -> {out}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
