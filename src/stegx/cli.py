
from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
import time
import zlib
from typing import Callable, List, Optional

from PIL import Image, UnidentifiedImageError

from stegx.io_sources import fetch_cover_to_tempfile, is_url
from stegx.kdf import KdfParams
from stegx.safe_paths import (
    PathValidationError,
    sink_safe_path,
    validate_user_path,
)
from stegx.shamir import combine_shares, split_secret
from stegx.constants import YK_CHALLENGE_NONCE_LEN
from stegx.sentinel import cover_fingerprint
from stegx.yubikey import (
    YUBIKEY_AVAILABLE,
    YubiKeyError,
    challenge_for_operation,
    resolve_yubikey_response,
)
from stegx.steganography import (
    EmbedOptions,
    calculate_lsb_capacity,
    embed_v2,
    extract_v2,
)
from stegx.exceptions import StegXError
from stegx.utils import (
    META_PANIC,
    META_PANIC_MODE,
    create_payload,
    create_payload_from_bytes,
    create_payload_from_files,
    parse_payload,
    parse_payload_full,
    save_extracted,
    save_extracted_file,
    setup_logging,
)

__version__ = "2.0.0"

def _build_version_string() -> str:
    def _present(mod_name: str) -> str:
        try:
            __import__(mod_name)
            return "ok"
        except ImportError:
            return "missing"

    from stegx.compression import available_algorithms
    from stegx.secure_memory import MEMORY_LOCK_AVAILABLE
    from stegx.yubikey import YUBIKEY_AVAILABLE

    parts = [f"stegx {__version__}"]
    parts.append("")
    parts.append("Core (required):")
    parts.append(f"  argon2-cffi    : {_present('argon2')}")
    parts.append(f"  cryptography   : {_present('cryptography')}")
    parts.append(f"  Pillow         : {_present('PIL')}")
    parts.append(f"  tqdm           : {_present('tqdm')}")
    parts.append("")
    parts.append("Optional:")
    parts.append(f"  zstandard      : {_present('zstandard')}")
    parts.append(f"  brotli         : {_present('brotli')}")
    parts.append(f"  zxcvbn         : {_present('zxcvbn')}")
    parts.append(f"  ykman (YubiKey): {'ok' if YUBIKEY_AVAILABLE else 'missing'}")
    parts.append(f"  numpy          : {_present('numpy')}")
    parts.append("")
    parts.append("Runtime capabilities:")
    parts.append(f"  memory locking : {'ok (mlock / VirtualLock)' if MEMORY_LOCK_AVAILABLE else 'missing'}")
    parts.append(f"  compression    : {', '.join(available_algorithms())}")
    return "\n".join(parts)

GENERIC_DECODE_ERROR = (
    "Extraction failed: wrong password, wrong keyfile, or image does not"
    " contain StegX data."
)

def _print_err(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)

def _print_ok(msg: str) -> None:
    print(msg)

def _win_pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    import ctypes
    from ctypes import wintypes
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetLastError.restype = wintypes.DWORD
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return kernel32.GetLastError() != 87

class _OutputLock:
    _MIN_STALE_SECONDS = 5

    def __init__(self, output_path: str):
        self._lock_path = output_path + ".stegx-lock"
        self._fd: Optional[int] = None

    def _try_create(self) -> bool:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            self._fd = os.open(self._lock_path, flags, 0o600)
        except FileExistsError:
            return False
        payload = f"{os.getpid()}\n{time.time():.3f}"
        os.write(self._fd, payload.encode("ascii"))
        return True

    def _steal_if_stale(self) -> bool:
        try:
            fd = os.open(self._lock_path, os.O_RDONLY)
        except OSError:
            return False
        pid = 0
        try:
            try:
                st = os.fstat(fd)
            except OSError:
                return False
            mtime = st.st_mtime
            if time.time() - mtime < self._MIN_STALE_SECONDS:
                return False
            try:
                raw = os.read(fd, 128)
            except OSError:
                return False
            try:
                pid_str = raw.decode("ascii", errors="ignore").splitlines()[0].strip()
                pid = int(pid_str)
            except (ValueError, IndexError):
                pid = -1
            alive = False
            if pid > 0:
                if os.name == "nt":
                    try:
                        import psutil
                        alive = psutil.pid_exists(pid)
                    except ImportError:
                        alive = _win_pid_is_alive(pid)
                else:
                    try:
                        os.kill(pid, 0)
                        alive = True
                    except ProcessLookupError:
                        alive = False
                    except PermissionError:

                        alive = True
            if alive:
                return False


            try:
                st2 = os.fstat(fd)
            except OSError:
                return False
            if st2.st_mtime != mtime:
                return False
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(self._lock_path)
            logging.warning(
                "Removed stale lock file %s (owning process is gone).",
                self._lock_path,
            )
        except OSError:
            return False
        return True

    def __enter__(self) -> "_OutputLock":
        if self._try_create():
            return self
        if self._steal_if_stale() and self._try_create():
            return self
        raise RuntimeError(
            f"Another stegx process appears to be writing to the same "
            f"output (lock file {self._lock_path} exists). If this is "
            f"stale, remove it manually and retry."
        )

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            if self._fd is not None:
                os.close(self._fd)
        except OSError:
            pass
        try:
            os.unlink(self._lock_path)
        except OSError:
            pass

def _output_path_is_traversal_free(path: str, allow_outside: bool = False) -> bool:
    if allow_outside:
        return True
    norm = os.path.normpath(path)
    parts = norm.replace("\\", "/").split("/")
    return ".." not in parts

def _bounded_int(lo: int, hi: int, name: str = "value"):
    def _check(raw: str) -> int:
        try:
            v = int(raw)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"{name} must be an integer, got {raw!r}"
            )
        if not (lo <= v <= hi):
            raise argparse.ArgumentTypeError(
                f"{name} must be between {lo} and {hi}, got {v}"
            )
        return v
    return _check


def _prompt_password(confirm: bool, label: str = "Password") -> str:
    pw = getpass.getpass(f"{label}: ")
    if not pw:
        raise ValueError(f"{label} cannot be empty.")
    if confirm:
        again = getpass.getpass(f"Confirm {label.lower()}: ")
        if pw != again:
            raise ValueError("Passwords do not match.")
    return pw

def _resolve_password(
    args: argparse.Namespace,
    confirm: bool,
    label: str = "Password",
    arg_name: str = "password",
) -> str:
    explicit = getattr(args, arg_name, None)
    if getattr(args, "password_stdin", False):
        pw = sys.stdin.readline().rstrip("\r\n")
        if not pw:
            raise ValueError(f"{label} read from stdin was empty.")
        return pw
    if explicit:
        logging.warning(
            "Passing the password via --%s exposes it to shell history and"
            " `ps`. Prefer the interactive prompt.",
            arg_name.replace("_", "-"),
        )
        return explicit
    return _prompt_password(confirm=confirm, label=label)

def _maybe_yubikey_response(
    args: argparse.Namespace, challenge: bytes, *, required: bool = False
) -> Optional[bytes]:
    want_yk = bool(getattr(args, "yubikey", False))
    resp_file = getattr(args, "yubikey_response_file", None)
    if not want_yk and not resp_file and not required:
        return None
    if not want_yk and not resp_file and required:
        raise ValueError(
            "This payload requires the YubiKey factor. Re-run with --yubikey "
            "(or --yubikey-response-file for tests)."
        )
    if resp_file is None and not YUBIKEY_AVAILABLE:
        raise ValueError(
            "--yubikey needs the ykman / yubikit packages. Install with "
            "`pip install ykman` or provide --yubikey-response-file."
        )
    try:
        return resolve_yubikey_response(challenge, response_file=resp_file)
    except YubiKeyError as e:
        raise ValueError(f"YubiKey interaction failed: {e}")

def _read_keyfile(path: Optional[str]) -> Optional[bytes]:
    if not path:
        return None


    safe_path = validate_user_path(path, kind="file", must_exist=True)


    with open(sink_safe_path(safe_path), "rb") as f:
        data = f.read()
    if not data:
        raise ValueError("Keyfile is empty.")
    return data


def _check_password_strength(password: str, strict: bool) -> None:
    try:
        from zxcvbn import zxcvbn
    except ImportError:
        logging.debug("zxcvbn not installed; skipping password-strength gate.")
        return
    result = zxcvbn(password)
    score = int(result.get("score", 0))
    feedback = result.get("feedback", {}).get("warning") or "Low entropy."
    if score < 3:
        msg = (
            f"Password strength is weak (zxcvbn score {score}/4). {feedback}"
            " Use a longer passphrase mixing words, numbers and punctuation."
        )
        if strict:
            raise ValueError(msg)
        logging.warning(msg)


FIPS_BANNED_COMPRESSION = {"lzma", "bz2", "zstd", "zstd_dict_v1", "brotli"}

def _apply_fips_policy(args: argparse.Namespace) -> None:
    if not getattr(args, "fips", False):
        return
    from stegx.fips import assert_fips_runtime

    assert_fips_runtime()
    if getattr(args, "dual_cipher", False):
        raise ValueError(
            "--fips forbids --dual-cipher (ChaCha20-Poly1305 is not FIPS-approved)."
        )
    if getattr(args, "yubikey", False):
        raise ValueError(
            "--fips forbids --yubikey (YubiKey slot 2 uses HMAC-SHA1, "
            "which is not on the FIPS 140 validated algorithm list)."
        )
    if getattr(args, "old_yubikey", False):
        raise ValueError(
            "--fips forbids --old-yubikey: the rewrap's unwrap step would "
            "invoke HMAC-SHA1, which is not on the FIPS 140 validated "
            "algorithm list."
        )


    kdf_selected = getattr(args, "kdf", None)
    compression_selected = getattr(args, "compression", None)
    if kdf_selected == "argon2id":
        logging.info("--fips: switching KDF from argon2id to pbkdf2.")
        args.kdf = "pbkdf2"
        args._fips_forced_kdf = True
    if compression_selected is not None and compression_selected != "fast":
        logging.info("--fips: forcing --compression=fast (zlib only).")
        args.compression = "fast"
        args._fips_forced_compression = True

def _build_embed_options(args: argparse.Namespace, keyfile_bytes: Optional[bytes]) -> EmbedOptions:
    _apply_fips_policy(args)
    kdf_id = args.kdf
    kdf_params: KdfParams
    if kdf_id == "argon2id":
        kdf_params = KdfParams.default_argon2id()
    elif kdf_id == "pbkdf2":
        kdf_params = KdfParams.default_pbkdf2()
    else:
        raise ValueError(f"Unknown KDF selection: {kdf_id}")

    return EmbedOptions(
        dual_cipher=args.dual_cipher,
        use_matrix_embedding=args.matrix_embedding,
        use_adaptive=args.adaptive,
        adaptive_cutoff=args.adaptive_cutoff,
        adaptive_cost_mode=getattr(args, "adaptive_mode", "laplacian"),
        max_fill_ratio=args.max_fill / 100.0,
        keyfile_bytes=keyfile_bytes,
        decoy_file_bytes=None,
        decoy_filename=None,
        decoy_password=None,
        always_split_cover=getattr(args, "always_split_cover", False),
        preserve_cover_encoding=not args.no_preserve_cover,
        compression=args.compress,
        kdf_params=kdf_params,
    )

def _resolve_cover_path(raw_path: str) -> tuple[str, Optional[str]]:
    if is_url(raw_path):
        tmp = fetch_cover_to_tempfile(raw_path)
        return tmp, tmp
    return raw_path, None


def _resolve_encode_files(args: argparse.Namespace) -> List[str]:
    raw_files = args.file if isinstance(args.file, list) else [args.file]
    for f in raw_files:
        if not os.path.isfile(f):
            raise FileNotFoundError(f"File to hide not found: {f}")
    return raw_files

def _resolve_encode_credentials(
    args: argparse.Namespace, cover_path: str
) -> "tuple[str, Optional[bytes], Optional[bytes], Optional[bytes]]":
    password = _resolve_password(args, confirm=True, label="Password")
    _check_password_strength(password, strict=args.strict_password)
    keyfile_bytes = _read_keyfile(args.keyfile)

    yk_nonce: Optional[bytes] = None
    yubikey_response: Optional[bytes] = None
    wants_yk = bool(
        getattr(args, "yubikey", False) or getattr(args, "yubikey_response_file", None)
    )
    if wants_yk:
        with Image.open(cover_path) as _img:
            _probe = _img.convert("RGBA") if _img.mode == "P" else _img
            fp = cover_fingerprint(_probe)
        yk_nonce = os.urandom(YK_CHALLENGE_NONCE_LEN)
        challenge = challenge_for_operation(yk_nonce, fp)
        yubikey_response = _maybe_yubikey_response(args, challenge)

    return password, keyfile_bytes, yubikey_response, yk_nonce

def _resolve_encode_decoy(
    args: argparse.Namespace, real_password: str
) -> "tuple[Optional[bytes], Optional[str], Optional[str]]":
    if not args.decoy_file:
        return None, None, None
    safe_decoy = validate_user_path(args.decoy_file, kind="file", must_exist=True)

    with open(sink_safe_path(safe_decoy), "rb") as f:
        decoy_bytes = f.read()
    decoy_name = os.path.basename(safe_decoy)
    decoy_password = args.decoy_password or _prompt_password(
        confirm=True, label="Decoy password"
    )
    _check_password_strength(decoy_password, strict=args.strict_password)
    if decoy_password == real_password:
        raise ValueError("Decoy password must differ from the real password.")
    return decoy_bytes, decoy_name, decoy_password

def _resolve_encode_panic(
    args: argparse.Namespace, real_password: str
) -> "tuple[Optional[str], Optional[bytes]]":
    if not getattr(args, "panic_password", None):
        return None, None
    if args.decoy_file:
        raise ValueError(
            "--panic-password and --decoy-file share the cover's decoy "
            "region; choose one or the other."
        )
    panic_password = args.panic_password
    _check_password_strength(panic_password, strict=args.strict_password)
    if panic_password == real_password:
        raise ValueError("Panic password must differ from the real password.")
    panic_marker_payload: Optional[bytes] = None
    if getattr(args, "panic_decoy", None):
        safe_panic_decoy = validate_user_path(
            args.panic_decoy, kind="file", must_exist=True
        )

        with open(sink_safe_path(safe_panic_decoy), "rb") as f:
            panic_marker_payload = f.read()
    return panic_password, panic_marker_payload

def _probe_cover_capacity(cover_path: str, original_arg: str) -> int:
    try:
        with Image.open(cover_path) as probe:
            if probe.mode == "P":
                probe = probe.convert("RGBA")
            elif probe.mode not in ("RGB", "RGBA", "L"):
                raise ValueError(f"Unsupported cover image mode: {probe.mode}.")
            return calculate_lsb_capacity(probe)
    except UnidentifiedImageError:
        raise ValueError(f"Cannot identify image file: {original_arg}")

def _attach_polyglot(saved_path: str, polyglot_files: Optional[List[str]]) -> None:
    if not polyglot_files:
        return
    from stegx.polyglot import build_zip_from_files, make_png_zip_polyglot


    safe_members = [
        validate_user_path(f, kind="file", must_exist=True)
        for f in polyglot_files
    ]


    safe_members = [sink_safe_path(p) for p in safe_members]
    zip_bytes = build_zip_from_files(safe_members)
    make_png_zip_polyglot(saved_path, zip_bytes)
    zip_names = ", ".join(os.path.basename(f) for f in safe_members)
    _print_ok(
        f"Polyglot PNG+ZIP written: {saved_path} (public ZIP side: [{zip_names}])"
    )

def perform_encode(args: argparse.Namespace) -> bool:
    tmp_cover: Optional[str] = None
    try:


        if not is_url(args.image):
            args.image = validate_user_path(
                args.image, kind="file", must_exist=True
            )


            args.image = sink_safe_path(args.image)
        args.output = sink_safe_path(validate_user_path(args.output))
        try:
            cover_path, tmp_cover = _resolve_cover_path(args.image)
        except ValueError as e:
            raise FileNotFoundError(f"Cover image not available: {e}")
        if not os.path.isfile(cover_path):
            raise FileNotFoundError(f"Cover image not found: {args.image}")

        raw_files = _resolve_encode_files(args)
        password, keyfile_bytes, yubikey_response, yk_nonce = _resolve_encode_credentials(
            args, cover_path
        )
        decoy_bytes, decoy_name, decoy_password = _resolve_encode_decoy(args, password)
        panic_password, panic_marker_payload = _resolve_encode_panic(args, password)

        capacity_bits = _probe_cover_capacity(cover_path, args.image)
        logging.info("Cover capacity ~= %d bits (%d bytes).", capacity_bits, capacity_bits // 8)

        payload_bytes = create_payload_from_files(
            raw_files,
            compress=args.compress,
            compression_mode=args.compression,
            show_progress=not getattr(args, "verbose", False),
        )


        if not _output_path_is_traversal_free(args.output, allow_outside=getattr(args, "allow_outside_cwd", False)):
            _print_err(
                f"Refusing to write outside the current directory: {args.output!r}. "
                "Pass --allow-outside-cwd to override."
            )
            return False

        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        if not args.output.lower().endswith(".png"):
            logging.warning("Output does not end with .png; saving as PNG.")

        options = _build_embed_options(args, keyfile_bytes)
        options.yubikey_response = yubikey_response
        options.yk_challenge_nonce = yk_nonce
        options.decoy_file_bytes = decoy_bytes
        options.decoy_filename = decoy_name
        options.decoy_password = decoy_password
        options.panic_password = panic_password
        options.panic_marker_payload = panic_marker_payload

        with _OutputLock(args.output):
            saved_path = embed_v2(cover_path, payload_bytes, args.output, password, options)
        names = ", ".join(os.path.basename(f) for f in raw_files)
        _maybe_audit(args, "encode", ok=True, cover_path=cover_path, stego_path=saved_path)

        _attach_polyglot(saved_path, getattr(args, "polyglot_zip", None))

        _print_ok(f"Successfully encoded [{names}] into '{saved_path}'.")
        return True
    except (StegXError, FileNotFoundError, ValueError, OSError, zlib.error) as e:
        logging.error("Encoding failed: %s", e)
        _print_err(f"Encoding failed: {e}")
        _maybe_audit(args, "encode", ok=False, note=type(e).__name__)
        return False
    except Exception as e:
        logging.exception("Unexpected encoding failure.")
        _print_err(f"Unexpected error: {e}")
        _maybe_audit(args, "encode", ok=False, note=type(e).__name__)
        return False
    finally:
        if tmp_cover:
            try:


                os.unlink(sink_safe_path(tmp_cover))
            except (OSError, PathValidationError):
                pass

def _decode_wants_stdout(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "stdout", False)) or args.destination == "-"

def _collect_flags_for_audit(args: argparse.Namespace) -> list:
    flags = []
    for attr in (
        "dual_cipher", "adaptive", "matrix_embedding",
        "strict_password", "always_split_cover", "fips",
        "yubikey", "no_preserve_cover",
    ):
        if getattr(args, attr, False):
            flags.append(f"--{attr.replace('_', '-')}")
    if getattr(args, "keyfile", None):
        flags.append("--keyfile")
    if getattr(args, "decoy_file", None):
        flags.append("--decoy-file")
    if getattr(args, "panic_password", None):
        flags.append("--panic-password")
    if getattr(args, "polyglot_zip", None):
        flags.append("--polyglot-zip")


    if getattr(args, "compression", None) and args.compression != "best":
        forced = getattr(args, "_fips_forced_compression", False)
        tag = "fips-forced" if forced else args.compression
        flags.append(f"--compression={tag}")
    if getattr(args, "kdf", None) and args.kdf != "argon2id":
        forced = getattr(args, "_fips_forced_kdf", False)
        tag = "fips-forced" if forced else args.kdf
        flags.append(f"--kdf={tag}")
    return flags

def _maybe_audit(args: argparse.Namespace, op: str, *, ok: bool,
                 cover_path: "Optional[str]" = None,
                 stego_path: "Optional[str]" = None,
                 note: "Optional[str]" = None) -> None:
    path = getattr(args, "audit_log", None)
    if not path:
        return
    try:
        from stegx.audit_log import append_record

        append_record(
            path, op,
            ok=ok,
            cover_path=cover_path,
            stego_path=stego_path,
            flags=_collect_flags_for_audit(args),
            note=note,
        )
    except Exception as e:
        logging.debug("audit: unexpected error in append_record: %s", e)

def perform_decode(args: argparse.Namespace) -> bool:
    try:


        args.image = sink_safe_path(
            validate_user_path(args.image, kind="file", must_exist=True)
        )

        to_stdout = _decode_wants_stdout(args)
        if not to_stdout:
            if args.destination is None:
                raise ValueError(
                    "A destination directory is required (or pass --stdout / -d -"
                    " to write the payload to stdout)."
                )
            args.destination = sink_safe_path(
                validate_user_path(args.destination)
            )
            if not os.path.exists(args.destination):
                os.makedirs(args.destination, exist_ok=True)
            elif not os.path.isdir(args.destination):
                raise NotADirectoryError(
                    f"Destination is not a directory: {args.destination}"
                )

        password = _resolve_password(args, confirm=False, label="Password")
        keyfile_bytes = _read_keyfile(args.keyfile)


        yk_factory: Optional[Callable[[bytes], bytes]] = None
        if getattr(args, "yubikey", False) or getattr(args, "yubikey_response_file", None):
            def yk_factory(challenge: bytes) -> bytes:
                return _maybe_yubikey_response(args, challenge, required=True)

        from stegx.steganography import extract_v2_with_region

        try:
            decrypted, matched_region = extract_v2_with_region(
                args.image,
                password,
                keyfile_bytes,
                yubikey_factory=yk_factory,
                allow_v1=getattr(args, "allow_v1", False),
            )
        except (StegXError, ValueError, OSError) as e:


            logging.debug("extract_v2 raised: %s", e)
            _print_err(GENERIC_DECODE_ERROR)
            return False

        try:
            filename, file_data, meta = parse_payload_full(decrypted)
        except (StegXError, ValueError, zlib.error):
            _print_err(GENERIC_DECODE_ERROR)
            return False

        if meta.get(META_PANIC):
            from stegx.panic import (
                PANIC_MODE_SILENT,
                destroy_real_region_in_place,
            )

            panic_mode = meta.get(META_PANIC_MODE, PANIC_MODE_SILENT)


            destroy_real_region_in_place(
                args.image, matched_region, panic_mode=panic_mode,
            )
            if panic_mode == PANIC_MODE_SILENT:
                _print_err(GENERIC_DECODE_ERROR)
                return False


        if to_stdout:


            try:
                sys.stdout.buffer.write(file_data)
                sys.stdout.buffer.flush()
            except BrokenPipeError:
                pass
            logging.info(
                "Wrote %d bytes of '%s' to stdout (original filename preserved in log only).",
                len(file_data), filename,
            )
            return True

        written = save_extracted(filename, file_data, meta, args.destination)
        if len(written) == 1:
            _print_ok(f"Successfully decoded to '{written[0]}'.")
        else:
            _print_ok(
                f"Successfully decoded {len(written)} files from bundle into "
                f"'{args.destination}'."
            )
        _maybe_audit(args, "decode", ok=True, stego_path=args.image)
        return True
    except (FileNotFoundError, ValueError, OSError, NotADirectoryError) as e:


        logging.debug("decoding setup error: %s", e)
        if isinstance(e, NotADirectoryError):
            _print_err(f"{e}")
        else:
            _print_err(GENERIC_DECODE_ERROR)
        _maybe_audit(args, "decode", ok=False, stego_path=args.image,
                     note=type(e).__name__)
        return False
    except Exception as e:
        logging.exception("Unexpected decoding failure.")
        _print_err(f"Unexpected error: {e}")
        _maybe_audit(args, "decode", ok=False, stego_path=args.image,
                     note=type(e).__name__)
        return False


def perform_shamir_split(args: argparse.Namespace) -> bool:
    try:


        args.file = sink_safe_path(
            validate_user_path(args.file, kind="file", must_exist=True)
        )
        if args.k > args.n:
            raise ValueError("Threshold k cannot exceed total shares n.")
        if len(args.cover) != args.n:
            raise ValueError(
                f"Expected {args.n} cover images (-n {args.n}), got {len(args.cover)}."
            )


        args.cover = [
            c if is_url(c) else sink_safe_path(
                validate_user_path(c, kind="file", must_exist=True)
            )
            for c in args.cover
        ]
        args.out_dir = sink_safe_path(validate_user_path(args.out_dir))

        password = _resolve_password(args, confirm=True, label="Password")
        keyfile_bytes = _read_keyfile(args.keyfile)


        with open(sink_safe_path(args.file), "rb") as f:
            secret = f.read()
        shares = split_secret(secret, args.k, args.n)
        os.makedirs(args.out_dir, exist_ok=True)

        for idx, (raw_cover, share_bytes) in enumerate(zip(args.cover, shares), start=1):
            cover_path, tmp_cover = _resolve_cover_path(raw_cover)
            try:
                if not os.path.isfile(cover_path):
                    raise FileNotFoundError(f"Cover not found: {raw_cover}")
                share_yk_nonce: Optional[bytes] = None
                share_yk_resp: Optional[bytes] = None
                if getattr(args, "yubikey", False) or getattr(args, "yubikey_response_file", None):
                    with Image.open(cover_path) as _img:
                        _probe = _img.convert("RGBA") if _img.mode == "P" else _img
                        _fp = cover_fingerprint(_probe)
                    share_yk_nonce = os.urandom(YK_CHALLENGE_NONCE_LEN)
                    share_yk_resp = _maybe_yubikey_response(
                        args, challenge_for_operation(share_yk_nonce, _fp)
                    )
                filename = f"{os.path.basename(args.file)}.share{idx:02d}"
                inner = create_payload_from_bytes(filename, share_bytes, compress=False)
                out_path = os.path.join(args.out_dir, f"stego_share_{idx:02d}.png")
                opts = _build_embed_options(args, keyfile_bytes)
                opts.yubikey_response = share_yk_resp
                opts.yk_challenge_nonce = share_yk_nonce
                opts.decoy_file_bytes = None
                opts.decoy_password = None


                with _OutputLock(out_path):
                    embed_v2(cover_path, inner, out_path, password, opts)
                _print_ok(f"Share {idx}/{args.n} embedded in {out_path}")
            finally:
                if tmp_cover:
                    try:
                        os.unlink(tmp_cover)
                    except OSError:
                        pass
        _print_ok(f"Done. Any {args.k} of {args.n} shares reconstruct the secret.")
        return True
    except (FileNotFoundError, ValueError, OSError) as e:
        logging.error("Shamir split failed: %s", e)
        _print_err(f"Shamir split failed: {e}")
        return False
    except Exception as e:
        logging.exception("Unexpected Shamir-split failure.")
        _print_err(f"Unexpected error: {e}")
        return False

def perform_rewrap(args: argparse.Namespace) -> bool:
    tmp_cover: Optional[str] = None
    scratch: Optional[str] = None
    try:


        args.image = sink_safe_path(
            validate_user_path(args.image, kind="file", must_exist=True)
        )
        if getattr(args, "output", None):
            args.output = sink_safe_path(validate_user_path(args.output))


        _apply_fips_policy(args)

        old_password = _prompt_password(confirm=False, label="Current password")
        new_password = _prompt_password(confirm=True, label="New password")
        if new_password == old_password:
            raise ValueError("New password must differ from the current password.")
        _check_password_strength(new_password, strict=args.strict_password)

        old_keyfile = _read_keyfile(getattr(args, "old_keyfile", None))
        new_keyfile = _read_keyfile(getattr(args, "keyfile", None))
        old_yk_args = argparse.Namespace(
            yubikey=getattr(args, "old_yubikey", False),
            yubikey_response_file=getattr(args, "old_yubikey_response_file", None),
        )
        new_yk_args = args


        _old_yk_resp: list = []

        def _old_yk_factory(challenge: bytes) -> bytes:
            resp = _maybe_yubikey_response(old_yk_args, challenge, required=True)
            _old_yk_resp.append(resp)
            return resp

        old_yk_factory: Optional[Callable[[bytes], bytes]] = (
            _old_yk_factory
            if (getattr(old_yk_args, "yubikey", False) or
                getattr(old_yk_args, "yubikey_response_file", None))
            else None
        )


        from stegx.steganography import (
            _all_positions,
            _derive_position_material,
            extract_v2_with_region,
        )
        from stegx.decoy import reorder_region, split_regions
        from stegx.sentinel import cover_fingerprint
        from stegx.panic import _overwrite_lsbs_randomly


        output_path = getattr(args, "output", None) or args.image


        with _OutputLock(output_path):
            try:
                raw_inner, matched_region = extract_v2_with_region(
                    args.image, old_password, old_keyfile, yubikey_factory=old_yk_factory,
                )
            except (ValueError, OSError) as e:
                _print_err(f"rewrap: cannot decrypt with current credentials ({e}).")
                _maybe_audit(args, "rewrap", ok=False, stego_path=args.image,
                             note="old-credentials-invalid")
                return False


            image = Image.open(args.image)
            image.load()
            if image.mode == "P":
                image = image.convert("RGBA")
            fingerprint = cover_fingerprint(image)
            all_positions = _all_positions(image)


            new_yk_nonce: Optional[bytes] = None
            new_yubikey: Optional[bytes] = None
            if (getattr(new_yk_args, "yubikey", False) or
                    getattr(new_yk_args, "yubikey_response_file", None)):
                new_yk_nonce = os.urandom(YK_CHALLENGE_NONCE_LEN)
                new_challenge = challenge_for_operation(new_yk_nonce, fingerprint)
                new_yubikey = _maybe_yubikey_response(new_yk_args, new_challenge)

            if matched_region == "real-full":
                old_region = list(all_positions)
            elif matched_region == "real-half":
                _decoy, real_region = split_regions(all_positions, fingerprint)
                old_region = list(real_region)
            elif matched_region == "decoy-half":
                decoy_region, _real = split_regions(all_positions, fingerprint)
                old_region = list(decoy_region)
            else:
                _print_err("rewrap: unrecognised match region; refusing to modify image.")
                _maybe_audit(args, "rewrap", ok=False, stego_path=args.image,
                             note=f"unknown-region:{matched_region}")
                return False

            old_seed, _sent, _decoy_seed = _derive_position_material(
                old_password, old_keyfile, fingerprint,
                _old_yk_resp[0] if _old_yk_resp else None,
            )
            old_ordered = reorder_region(old_region, old_seed)
            _overwrite_lsbs_randomly(image, old_ordered)


            import tempfile as _tempfile
            scratch_dir = os.path.dirname(os.path.abspath(args.image)) or "."
            _sc_fd, scratch = _tempfile.mkstemp(
                dir=scratch_dir, prefix=".stegx_rewrap_", suffix=".tmp",
            )
            os.close(_sc_fd)
            image.save(scratch, format="PNG", pnginfo=None, optimize=False)
            image.close()


            options = _build_embed_options(args, new_keyfile)
            options.yubikey_response = new_yubikey
            options.yk_challenge_nonce = new_yk_nonce
            options.decoy_file_bytes = None
            options.decoy_password = None
            options.panic_password = None
            options.always_split_cover = (matched_region != "real-full")


            saved_path = embed_v2(scratch, raw_inner, output_path, new_password, options)


        if os.path.abspath(saved_path) == os.path.abspath(scratch):
            scratch = None

        _print_ok(f"Rewrapped '{args.image}' -> '{saved_path}' with the new credentials.")
        _maybe_audit(args, "rewrap", ok=True, stego_path=saved_path,
                     note=f"old-region={matched_region}")
        return True
    except (FileNotFoundError, ValueError, OSError) as e:
        logging.error("rewrap failed: %s", e)
        _print_err(f"rewrap failed: {e}")
        _maybe_audit(args, "rewrap", ok=False, note=type(e).__name__)
        return False
    except Exception as e:
        logging.exception("rewrap unexpected failure.")
        _print_err(f"Unexpected error: {e}")
        _maybe_audit(args, "rewrap", ok=False, note=type(e).__name__)
        return False
    finally:
        if scratch and os.path.exists(scratch):
            try:
                os.unlink(scratch)
            except OSError:
                pass
        if tmp_cover and os.path.exists(tmp_cover):
            try:
                os.unlink(tmp_cover)
            except OSError:
                pass

def perform_pick_cover(args: argparse.Namespace) -> bool:
    from stegx.cover_selector import pick_best_cover

    try:
        if not os.path.isdir(args.dir):
            raise NotADirectoryError(f"Cover directory not found: {args.dir}")
        if args.payload and not os.path.isfile(args.payload):
            raise FileNotFoundError(f"Payload file not found: {args.payload}")

        payload_size = os.path.getsize(args.payload) if args.payload else args.size
        if payload_size is None or payload_size <= 0:
            raise ValueError("Supply either --payload FILE or --size BYTES.")

        best, ranked = pick_best_cover(args.dir, payload_size)

        print(f"Payload size: {payload_size:,} bytes ({payload_size * 8:,} bits)")
        print(f"Candidates  : {len(ranked)} images scanned in {args.dir}")
        print()
        print(f"{'score':>8}  {'W x H':>11}  {'mode':<5} {'capacity (B)':>14}  {'entropy':>7}  path")
        print("-" * 80)
        for c in ranked[: args.limit]:
            marker = " " if c.enough_capacity else "x"
            print(
                f"{marker} {c.score:>6.2f}  {c.width:>5} x {c.height:<3} "
                f"{c.mode:<5} {c.capacity_bits // 8:>14,}  {c.entropy:>7.4f}  {c.path}"
            )
        if best is None:
            print()
            print("No candidate has enough capacity. Use a larger image or split the payload.")
            return False
        print()
        print(f"Best pick: {best.path}")
        return True
    except (FileNotFoundError, NotADirectoryError, ValueError, OSError) as e:
        _print_err(f"pick-cover failed: {e}")
        return False

def perform_benchmark(args: argparse.Namespace) -> bool:
    import os
    import time

    from stegx.compression import (
        MODE_BEST,
        MODE_FAST,
        available_algorithms,
        compress_best,
        ratio_report,
    )
    from stegx.kdf import (
        KdfParams,
        calibrate_argon2_for_target_ms,
        derive_master_key,
    )

    iterations = max(1, int(args.iterations))
    size_kib = max(1, int(args.size_kib))

    if getattr(args, "calibrate", False):
        target_ms = max(100, int(getattr(args, "target_ms", 500)))
        print(f"\n=== Argon2id calibration (target ~{target_ms} ms) ===")
        tuned = calibrate_argon2_for_target_ms(target_ms=target_ms)
        print(
            f"Recommended Argon2id params for this machine:\n"
            f"  time_cost      = {tuned.time_cost}\n"
            f"  memory_cost_kib= {tuned.memory_cost_kib} "
            f"({tuned.memory_cost_kib / 1024:.1f} MiB)\n"
            f"  parallelism    = {tuned.parallelism}"
        )
        print(
            "\nThese values are compiled into the default profile at\n"
            "  stegx/kdf.py::ARGON2_TIME_COST / ARGON2_MEMORY_COST_KIB /\n"
            "  ARGON2_PARALLELISM\n"
            "— bump them there if you want the project-wide default to change."
        )
        return True
    sample_text = (
        b"The quick brown fox jumps over the lazy dog. "
        b"StegX benchmark corpus 0123456789 {}[];:<>?,./\\|\n"
    )
    sample = (sample_text * ((size_kib * 1024 // len(sample_text)) + 1))[: size_kib * 1024]

    print(f"\n=== Argon2id KDF timing ({iterations} iterations) ===")
    params = KdfParams.default_argon2id()
    print(
        f"Default parameters: time_cost={params.time_cost}, "
        f"memory={params.memory_cost_kib} KiB, parallelism={params.parallelism}"
    )

    salt = os.urandom(16)
    timings = []
    for i in range(iterations):
        t0 = time.perf_counter()
        derive_master_key("benchmark-password-XYZ-123", salt, params)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        timings.append(elapsed_ms)
        print(f"  run {i+1}/{iterations}: {elapsed_ms:7.1f} ms")
    avg = sum(timings) / len(timings)
    print(f"  mean: {avg:.1f} ms (min {min(timings):.1f}, max {max(timings):.1f})")

    if avg < 300:
        rec = (
            f"Your machine runs the default Argon2id params in {avg:.0f} ms -- "
            "you can safely raise memory_cost_kib to strengthen brute-force "
            "resistance without noticeable latency."
        )
    elif avg > 2000:
        rec = (
            f"Argon2id took {avg:.0f} ms on average -- if UX matters, consider "
            "lowering memory_cost_kib to 32768 or time_cost to 2."
        )
    else:
        rec = f"Argon2id latency ({avg:.0f} ms) is within the recommended 0.3-2 s window."
    print(f"Recommendation: {rec}")

    print(f"\n=== Compression multiplexer ({size_kib} KiB of mixed ASCII) ===")
    print(f"Available algorithms: {', '.join(available_algorithms())}")

    t0 = time.perf_counter()
    fast_alg, fast_blob = compress_best(sample, mode=MODE_FAST)
    fast_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    best_alg, best_blob = compress_best(sample, mode=MODE_BEST)
    best_ms = (time.perf_counter() - t0) * 1000

    print(f"  --compression fast: {ratio_report(len(sample), len(fast_blob))} "
          f"via {fast_alg} ({fast_ms:.1f} ms)")
    print(f"  --compression best: {ratio_report(len(sample), len(best_blob))} "
          f"via {best_alg} ({best_ms:.1f} ms)")
    if len(fast_blob) > 0:
        savings = (1 - len(best_blob) / len(fast_blob)) * 100
        print(f"  best saves {savings:+.1f}% over fast (at {best_ms - fast_ms:.0f} ms extra cost).")

    print(f"\n=== Estimated wall-clock for full encode ===")
    total_ms = 2 * avg + best_ms
    print(f"  Argon2id x 2 ({2*avg:.0f} ms) + compression ({best_ms:.0f} ms) "
          f"~= {total_ms:.0f} ms")

    print()
    return True

def perform_shamir_combine(args: argparse.Namespace) -> bool:
    try:

        args.destination = sink_safe_path(validate_user_path(args.destination))
        args.image = [
            sink_safe_path(
                validate_user_path(p, kind="file", must_exist=True)
            )
            for p in args.image
        ]
        if not os.path.isdir(args.destination):
            os.makedirs(args.destination, exist_ok=True)
        password = _resolve_password(args, confirm=False, label="Password")
        keyfile_bytes = _read_keyfile(args.keyfile)

        wants_yk = getattr(args, "yubikey", False) or getattr(args, "yubikey_response_file", None)
        shares: List[bytes] = []
        for stego_path in args.image:
            yk_factory: Optional[Callable[[bytes], bytes]] = None
            if wants_yk:
                def yk_factory(challenge: bytes, _p=stego_path) -> bytes:
                    return _maybe_yubikey_response(args, challenge, required=True)
            decrypted = extract_v2(
                stego_path,
                password,
                keyfile_bytes,
                yubikey_factory=yk_factory,
            )
            _filename, share_bytes = parse_payload(decrypted)
            shares.append(share_bytes)

        secret = combine_shares(shares)
        output_name = os.path.basename(args.output or "recovered_secret.bin")
        output_path = os.path.join(args.destination, output_name)


        from stegx.safe_paths import ensure_under_base

        ensure_under_base(output_path, args.destination)

        with open(sink_safe_path(output_path), "wb") as f:
            f.write(secret)
        _print_ok(f"Combined {len(shares)} shares into {output_path}.")
        return True
    except (FileNotFoundError, ValueError, OSError) as e:
        logging.error("Shamir combine failed: %s", e)
        _print_err(f"Shamir combine failed: {e}")
        return False
    except Exception as e:
        logging.exception("Unexpected Shamir-combine failure.")
        _print_err(f"Unexpected error: {e}")
        return False


def _add_common_embed_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--password", metavar="PASSWORD", default=None,
                   help="Password (discouraged -- leaks into shell history; default: interactive prompt).")
    p.add_argument("--password-stdin", action="store_true",
                   help="Read the password from a single line of stdin.")
    p.add_argument("--keyfile", metavar="PATH", default=None,
                   help="Optional keyfile mixed into the KDF input (acts as a second factor).")
    p.add_argument("--yubikey", action="store_true",
                   help="Require a YubiKey HMAC-SHA1 challenge-response (slot 2) as a "
                        "second factor. Needs `pip install ykman`.")
    p.add_argument("--yubikey-response-file", metavar="PATH", default=None,
                   help=argparse.SUPPRESS)
    p.add_argument("--kdf", choices=("argon2id", "pbkdf2"), default="argon2id",
                   help="Password-based KDF (default: argon2id).")
    p.add_argument("--dual-cipher", action="store_true",
                   help="Layer ChaCha20-Poly1305 over AES-256-GCM. Both keys "
                        "derive from the same password-master via HKDF, so "
                        "this protects only against a catastrophic break in "
                        "one of the two algorithms — not against a password "
                        "break. Incompatible with --fips (ChaCha is not FIPS).")
    p.add_argument("--adaptive", action="store_true",
                   help="Embed only in high-edge-cost regions to resist CNN steganalysers.")
    p.add_argument("--adaptive-cutoff", type=float, default=0.40,
                   help="Percentile cutoff for --adaptive (0-1, default 0.40).")
    p.add_argument("--adaptive-mode", choices=("laplacian", "hill"), default="laplacian",
                   help="Cost map used by --adaptive: 'laplacian' (default, fast) "
                        "or 'hill' (Li et al. 2014, stronger against CNN steganalysers).")
    p.add_argument("--matrix-embedding", action="store_true",
                   help="Use F5-style Hamming(7,3) matrix embedding for the ciphertext body.")
    p.add_argument("--max-fill", type=float, default=25.0,
                   help="Refuse payloads that fill more than this percentage of capacity (default: 25%%).")
    p.add_argument("--strict-password", action="store_true",
                   help="Reject (rather than warn on) passwords with zxcvbn score < 3.")
    p.add_argument("--no-preserve-cover", action="store_true",
                   help="Do not mirror the cover's PNG encoder parameters on save.")
    p.add_argument("--audit-log", metavar="PATH", default=None,
                   help="Append a hash-chained JSONL audit record for this operation "
                        "(timestamp, op, cover/stego SHA-256, flag-set, ok/fail). "
                        "Payload contents are never logged.")
    p.add_argument("--no-compress", action="store_false", dest="compress", default=True,
                   help="Disable compression of the hidden file.")
    p.add_argument("--compression", choices=("fast", "best"), default="best",
                   help="Compression profile: 'fast' = zlib only, 'best' (default) = try"
                        " zlib, lzma, bz2, zstd, brotli and pick the smallest output.")
    p.add_argument("--always-split-cover", action="store_true",
                   help="Paranoia: always split the cover into two halves and fill the "
                        "decoy half with random bits even when no --decoy-file is set, "
                        "so an observer cannot detect decoy-mode usage. Halves cover "
                        "capacity permanently.")
    p.add_argument("--fips", action="store_true",
                   help="Restrict to FIPS 140-validated primitives: PBKDF2-HMAC-SHA256, "
                        "AES-256-GCM, HKDF-SHA256, zlib-only compression. Refuses "
                        "Argon2id, ChaCha20-Poly1305, brotli, lzma, bz2, zstd, and "
                        "YubiKey HMAC-SHA1. Requires a FIPS-validated cryptography "
                        "backend at runtime.")
    p.add_argument("--allow-outside-cwd", action="store_true",
                   help="Permit writing the stego output outside the current working "
                        "directory (disables the anti-traversal check on --output).")

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegx",
        description=f"StegX v{__version__}: authenticated LSB steganography with Argon2id + AES-GCM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  stegx encode -i cover.png -f secret.zip -o stego.png\n"
            "  stegx encode -i cover.png -f real.zip -o stego.png --decoy-file harmless.txt\n"
            "  stegx decode -i stego.png -d ./out\n"
            "  stegx shamir-split -k 3 -n 5 -f secret.bin -c c1.png c2.png c3.png c4.png c5.png -O shares/\n"
            "  stegx shamir-combine -i shares/stego_share_01.png shares/stego_share_02.png"
            " shares/stego_share_03.png -d ./out -o recovered.bin\n"
        ),
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=_build_version_string(),
        help="Show the version banner, including which optional extras are available.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")

    sub = parser.add_subparsers(dest="mode", required=True)

    enc = sub.add_parser("encode", help="Hide a file in a cover image.")
    enc.add_argument("-i", "--image", required=True, metavar="COVER")
    enc.add_argument("-f", "--file", required=True, metavar="FILE", nargs="+",
                     help="One or more files to hide. Multiple files are "
                          "tarred up transparently; the decoder unpacks them.")
    enc.add_argument("-o", "--output", required=True, metavar="OUTPUT_PNG")
    enc.add_argument("--decoy-file", metavar="PATH", default=None,
                     help="Optional decoy payload for plausible deniability.")
    enc.add_argument("--decoy-password", metavar="PASSWORD", default=None,
                     help="Password for the decoy (prompted if omitted and --decoy-file is set).")
    enc.add_argument("--panic-password", metavar="PASSWORD", default=None,
                     help="Arm self-destruct: typing this password at decode time wipes "
                          "the real region's LSBs before reporting success/failure. "
                          "Mutually exclusive with --decoy-file.")
    enc.add_argument("--panic-decoy", metavar="PATH", default=None,
                     help="Sacrificial payload returned after panic destruction "
                          "(omit to use silent mode — generic error, no output).")
    enc.add_argument("--polyglot-zip", metavar="PATH", nargs="+", default=None,
                     help="After encoding, append a ZIP archive containing the listed "
                          "files to the stego PNG so it is simultaneously a valid PNG "
                          "(viewed normally) and a valid ZIP (extractable with unzip). "
                          "The ZIP is a public side-channel; the hidden StegX payload "
                          "is unaffected.")
    _add_common_embed_flags(enc)

    dec = sub.add_parser("decode", help="Extract a hidden file from a stego image.")
    dec.add_argument("-i", "--image", required=True, metavar="STEGO")
    dec.add_argument("-d", "--destination", metavar="OUT_DIR", default=None,
                     help="Directory to write the extracted file. Use '-' or --stdout "
                          "to write the payload to stdout instead.")
    dec.add_argument("--stdout", action="store_true",
                     help="Write the decrypted payload to stdout instead of a file.")
    dec.add_argument("-p", "--password", metavar="PASSWORD", default=None)
    dec.add_argument("--password-stdin", action="store_true")
    dec.add_argument("--keyfile", metavar="PATH", default=None)
    dec.add_argument("--yubikey", action="store_true",
                     help="Supply a YubiKey HMAC-SHA1 response on the FLAG_YUBIKEY-bound payload.")
    dec.add_argument("--yubikey-response-file", metavar="PATH", default=None,
                     help=argparse.SUPPRESS)
    dec.add_argument("--audit-log", metavar="PATH", default=None,
                     help="Append a hash-chained audit record (see `encode --audit-log`).")
    dec.add_argument("--allow-v1", action="store_true",
                     help="Allow decoding of legacy StegX v1 stego images. "
                          "v1 uses weaker PBKDF2 parameters and an always-on "
                          "pixel scan, so it is off by default to prevent a "
                          "downgrade attack and a CPU-timing side channel.")

    spl = sub.add_parser("shamir-split",
                         help="Split a secret file into k-of-n stego shares.")
    spl.add_argument("-k", type=_bounded_int(1, 255, name="-k"),
                     required=True, metavar="THRESHOLD")
    spl.add_argument("-n", type=_bounded_int(1, 255, name="-n"),
                     required=True, metavar="TOTAL_SHARES")
    spl.add_argument("-f", "--file", required=True, metavar="SECRET_FILE")
    spl.add_argument("-c", "--cover", nargs="+", required=True, metavar="COVER_PNG",
                     help="n cover images, one per share.")
    spl.add_argument("-O", "--out-dir", required=True, metavar="OUT_DIR",
                     help="Directory to write stego_share_XX.png files.")
    _add_common_embed_flags(spl)

    bench = sub.add_parser("benchmark",
                           help="Measure Argon2id / compression performance on this machine.")
    bench.add_argument("--iterations", type=int, default=3, metavar="N",
                       help="Number of Argon2id samples to average (default: 3).")
    bench.add_argument("--size-kib", type=int, default=64, metavar="K",
                       help="Sample-payload size in KiB for the compression benchmark (default: 64).")
    bench.add_argument("--calibrate", action="store_true",
                       help="Run an Argon2id cost-sweep and recommend memory_cost_kib "
                            "that hits roughly --target-ms on this machine.")
    bench.add_argument("--target-ms", type=int, default=500, metavar="MS",
                       help="Target Argon2id latency in milliseconds for --calibrate "
                            "(default: 500).")

    rw = sub.add_parser("rewrap",
                        help="Rotate password / keyfile / yubikey on an existing stego "
                             "image without leaking plaintext to disk.")
    rw.add_argument("-i", "--image", required=True, metavar="STEGO")
    rw.add_argument("-o", "--output", metavar="OUT_PNG", default=None,
                    help="Write the rewrapped stego here (default: overwrite input).")
    rw.add_argument("--old-keyfile", metavar="PATH", default=None,
                    help="Keyfile currently bound to the stego image.")
    rw.add_argument("--keyfile", metavar="PATH", default=None,
                    help="Keyfile to bind on the new stego image (optional).")
    rw.add_argument("--old-yubikey", action="store_true",
                    help="The stego is currently sealed with a YubiKey factor.")
    rw.add_argument("--old-yubikey-response-file", metavar="PATH", default=None,
                    help=argparse.SUPPRESS)
    rw.add_argument("--yubikey", action="store_true",
                    help="Seal the rewrapped stego with a YubiKey factor going forward.")
    rw.add_argument("--yubikey-response-file", metavar="PATH", default=None,
                    help=argparse.SUPPRESS)
    rw.add_argument("--kdf", choices=("argon2id", "pbkdf2"), default="argon2id",
                    help="KDF for the NEW wrapping (default: argon2id).")
    rw.add_argument("--dual-cipher", action="store_true")
    rw.add_argument("--adaptive", action="store_true")
    rw.add_argument("--adaptive-cutoff", type=float, default=0.40)
    rw.add_argument("--adaptive-mode", choices=("laplacian", "hill"), default="laplacian")
    rw.add_argument("--matrix-embedding", action="store_true")
    rw.add_argument("--max-fill", type=float, default=100.0)
    rw.add_argument("--strict-password", action="store_true")
    rw.add_argument("--no-preserve-cover", action="store_true")
    rw.add_argument("--no-compress", action="store_false", dest="compress", default=True)
    rw.add_argument("--compression", choices=("fast", "best"), default="best")
    rw.add_argument("--always-split-cover", action="store_true")
    rw.add_argument("--fips", action="store_true")
    rw.add_argument("--audit-log", metavar="PATH", default=None)

    pick = sub.add_parser("pick-cover",
                          help="Rank covers in a directory by capacity + entropy for a given payload.")
    pick.add_argument("--dir", required=True, metavar="COVER_DIR",
                      help="Directory containing candidate cover images.")
    pick.add_argument("--payload", metavar="FILE", default=None,
                      help="Payload file — size used to check capacity.")
    pick.add_argument("--size", type=int, metavar="BYTES", default=None,
                      help="Payload size in bytes (use instead of --payload).")
    pick.add_argument("--limit", type=int, default=20, metavar="N",
                      help="Show at most N candidates (default: 20).")

    cmb = sub.add_parser("shamir-combine",
                         help="Recover a secret from k-or-more stego shares.")
    cmb.add_argument("-i", "--image", nargs="+", required=True, metavar="STEGO_SHARE")
    cmb.add_argument("-d", "--destination", required=True, metavar="OUT_DIR")
    cmb.add_argument("-o", "--output", metavar="FILENAME", default=None,
                     help="Filename for the recovered secret (default: recovered_secret.bin).")
    cmb.add_argument("-p", "--password", metavar="PASSWORD", default=None)
    cmb.add_argument("--password-stdin", action="store_true")
    cmb.add_argument("--keyfile", metavar="PATH", default=None)
    cmb.add_argument("--yubikey", action="store_true")
    cmb.add_argument("--yubikey-response-file", metavar="PATH", default=None,
                     help=argparse.SUPPRESS)

    return parser

def main(argv: Optional[List[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    logging.debug("StegX v%s started (mode=%s).", __version__, args.mode)

    if args.mode == "encode":
        ok = perform_encode(args)
    elif args.mode == "decode":
        ok = perform_decode(args)
    elif args.mode == "shamir-split":
        ok = perform_shamir_split(args)
    elif args.mode == "shamir-combine":
        ok = perform_shamir_combine(args)
    elif args.mode == "benchmark":
        ok = perform_benchmark(args)
    elif args.mode == "pick-cover":
        ok = perform_pick_cover(args)
    elif args.mode == "rewrap":
        ok = perform_rewrap(args)
    else:
        parser.error(f"Unknown mode: {args.mode}")
        return

    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
