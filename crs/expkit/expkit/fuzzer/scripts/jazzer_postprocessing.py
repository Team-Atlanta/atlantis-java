#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import signal
import sys
import time
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Tuple

SANITIZERS = [
    "os command injection",
    "server side request forgery (ssrf)",
    "remote code execution",
    "sql injection",
    "remote jndi lookup",
    "ldap injection",
    "xpath injection",
    "load arbitrary library",
    "regular expression injection",
    "script engine injection",
    "file path traversal",
]

FUZZ_START_LINE_PTRN = re.compile(
    r"^(\d+)\sOpenJDK 64-Bit Server VM warning: Option CriticalJNINatives was deprecated in version 16.0 and will likely be removed in a future release."
)

OLD_LIBFUZZER_COV_LINE_PTRN = re.compile(r"^#(\d+).*cov: (\d+) ft: (\d+).*rss: (\w+)")
OLD_LIBFUZZER_NOCOV_LINE_PTRN = re.compile(r"^#(\d+)(.*)ft: (\d+).*rss: (\w+)")
LIBFUZZER_COV_LINE_PTRN = re.compile(
    r"^(\d+)\s#(\d+).*cov: (\d+) ft: (\d+).*rss: (\w+)"
)
LIBFUZZER_NOCOV_LINE_PTRN = re.compile(r"^(\d+)\s#(\d+)(.*)ft: (\d+).*rss: (\w+)")

# NOTE: we only use 1 client in jazzer-libafl, so just parse this client line for exact stats
LIBAFL_JAZZER_COV_LINE_PTRN = re.compile(
    r"^(\d+)[\s\t]+\(CLIENT\) .*, executions: (\d+), .*, cmps: (\d+)/\d+ .*, edges: (\d+)/\d+"
)

OLD_LIBFUZZER_CRASH_LINE_PTRN = re.compile(r"^(== Java Exception:.*)")
LIBFUZZER_CRASH_LINE_PTRN = re.compile(r"^(\d+)\s(== Java Exception:.*)")

OLD_LIBFUZZER_NATIVE_CRASH_LINE_PTRN = re.compile(
    r"^==\d+==(ERROR: AddressSanitizer:.*)"
)
LIBFUZZER_NATIVE_CRASH_LINE_PTRN = re.compile(
    r"^(\d+)\s==\d+==(ERROR: AddressSanitizer:.*)"
)

OLD_LIBFUZZER_DEDUP_CRASH_TOKEN = re.compile(r"^DEDUP_TOKEN:\s+([0-9a-f]+)")
LIBFUZZER_DEDUP_CRASH_TOKEN = re.compile(r"^(\d+)\sDEDUP_TOKEN:\s+([0-9a-f]+)")

OLD_LIBFUZZER_CRASH_STACK_LINE_PTRN = re.compile(r"^\s+(at .+\(.+:\d+\))")
LIBFUZZER_CRASH_STACK_LINE_PTRN = re.compile(r"^(\d+)\s+(at .+\(.+:\d+\))")

OLD_CRASH_ARTIFACT_LINE_PTRN = re.compile(
    r"^artifact_prefix=.*; Test unit written to .*/artifacts/((crash|timeout)-[a-z0-9]+)"
)
CRASH_ARTIFACT_LINE_PTRN = re.compile(
    r"^(\d+)\sartifact_prefix=.*; Test unit written to .*/artifacts/((crash|timeout)-[a-z0-9]+)"
)
OLD_CRASH_REPRO_ARTIFACT_LINE_PTRN = re.compile(
    r"^Executed (\S*) in \d+ ms"
)
CRASH_REPRO_ARTIFACT_LINE_PTRN = re.compile(
    r"^(\d+)\sExecuted (\S*) in \d+ ms"
)
# NOTE: TODO: libafl-jazzer currently does not log timeout artifact info
LIBAFL_JAZZER_CRASH_ARTIFACT_LINE_PTRN = re.compile(
    r"^(\d+)\s\[libafl\] Received jazzer death callback! Dumping corpus as crash to .*/artifacts/(crash-[a-z0-9]+)"
)

OLD_BEEP_COORD_LINE_PTRN = re.compile(r"^INFO: BEEP COORDINATE HIT @ (.*)")

BEEP_COORD_LINE_PTRN = re.compile(r"^(\d+)\sINFO: BEEP COORDINATE HIT @ (.*)")

JAZZER_EXIT_LOG = "@@@@@ exit code of Jazzer"

keep_full_detail = True if os.getenv("JAZZER_KEEP_FULL_DETAIL", "") == "on" else False

artifact_dir = os.getenv("JAZZER_ARTIFACT_DIR", "/sth-never-exist-artifact-dir")
artifact_dir = artifact_dir if os.path.exists(artifact_dir) else None

is_libafl_jazzer = False

CRS_ERR = "CRS-JAVA-ERR-jazzer_pp"
CRS_WARN = "CRS-JAVA-WARN-jazzer_pp"

# If no cov/ft/exec info after this many restarts, fall through to naive fuzzer
FALL_THROUGH_THRESHOLD = 66

# Global logger
logger = None


# Set up global logger that outputs to file (with rolling behavior) or stdout
def setup_logger(log_file_path=None, max_bytes=1024 * 1024 * 1024, backup_count=1):
    """
    Sets up a global logger that either:
    - Writes to a rolling log file when log_file_path is provided
    - Writes to stdout when log_file_path is None

    Args:
        log_file_path: Path to the log file (None for stdout)
        max_bytes: Maximum log file size (default 1GB)
        backup_count: Number of backup files to keep (default 0)
    """
    global logger

    if logger is not None:
        # Logger already configured
        return

    logger = logging.getLogger("jazzer_postprocessing")
    logger.setLevel(logging.INFO)

    # Create a formatter that just outputs the message
    formatter = logging.Formatter("%(message)s")

    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    if log_file_path:
        # Create RotatingFileHandler with 1GB max size and no backups
        handler = RotatingFileHandler(
            log_file_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    else:
        # Output to stdout when no log file is specified
        handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(formatter)
    logger.addHandler(handler)


def is_libafl_jazzer_flag_line(line: str) -> bool:
    return (
        "[libafl]" in line
        and "custom_mutation:" in line
        and "custom_crossover:" in line
    )


def is_known_sanitizer(sanitizer: str) -> bool:
    for s in SANITIZERS:
        if s in sanitizer.lower():
            return True
    else:
        return False


def is_security_crash(crash: str) -> bool:
    checkers = [
        # Filter for crashes that contain "code_intelligence"
        lambda c: "code_intelligence" in c.split(":")[1],
        # Filter out "Stack overflow" crashes
        lambda c: "Stack overflow (use " not in c,
        # Filter out "Out of memory" crashes
        lambda c: "Out of memory" not in c,
    ]

    for checker in checkers:
        if not checker(crash):
            # Not really security significant crash
            return False
    else:
        return True


def crash_2_sanitizer(crash: str) -> str:
    if not is_security_crash(crash):
        # Non-security crash, do dedup by exp type
        if "Out of memory" in crash:
            return f"OOM-{crash}"
        if "Stack overflow" in crash:
            return f"StackOverflow-{crash}"
        if "AddressSanitizer" in crash:
            return f"ASAN-{crash}"
        # E.g.,: == Java Exception: java.lang.NoClassDefFoundError: org/apache/logging/log4j/Logger
        return (
            f"NONSEC-{crash.split(':')[1].strip() if ':' in crash else crash.strip()}"
        )

    for sanitizer in SANITIZERS:
        if sanitizer in crash.lower():
            return sanitizer
    else:
        return "UNKNOWN SANITIZER"


def _convert_memory_to_bytes(memory_str):
    units = {
        "b": 1,
        "kb": 1024,
        "mb": 1024**2,
        "gb": 1024**3,
        "tb": 1024**4,
        "pb": 1024**5,
    }

    memory_str = memory_str.strip().lower()
    number = ""

    for char in memory_str:
        if char.isdigit() or char == ".":
            number += char
        else:
            break

    unit = memory_str[len(number) :].strip()

    if unit not in units:
        # raise ValueError(f"Unknown memory unit: {unit}")
        return 0

    return int(float(number) * units[unit])


def _parse_cov_line(line: str, initial_timestamp: Optional[int]) -> Optional[Tuple]:
    global is_libafl_jazzer

    if is_libafl_jazzer:
        match = LIBAFL_JAZZER_COV_LINE_PTRN.match(line)
        if match:
            timestamp, roundno, ft, cov = (
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
            )
            rss = 0
            elapsed_time = (
                timestamp - initial_timestamp if initial_timestamp is not None else None
            )
            return roundno, elapsed_time, cov, ft, rss
        return None
    else:
        has_cov = "cov:" in line
        if has_cov:
            match = LIBFUZZER_COV_LINE_PTRN.match(line)
        else:
            match = LIBFUZZER_NOCOV_LINE_PTRN.match(line)
        if match:
            timestamp, roundno, cov, ft, rss = (
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)) if has_cov else 0,
                int(match.group(4)),
                _convert_memory_to_bytes(match.group(5)),
            )
            elapsed_time = (
                timestamp - initial_timestamp if initial_timestamp is not None else None
            )
            return roundno, elapsed_time, cov, ft, rss
        else:
            if has_cov:
                match = OLD_LIBFUZZER_COV_LINE_PTRN.match(line)
            else:
                match = OLD_LIBFUZZER_NOCOV_LINE_PTRN.match(line)
            if match:
                roundno, cov, ft, rss = (
                    int(match.group(1)),
                    int(match.group(2)) if has_cov else 0,
                    int(match.group(3)),
                    _convert_memory_to_bytes(match.group(4)),
                )
                return roundno, None, cov, ft, rss
        return None


def _replace_hex_addr(crash: str) -> str:
    """Remove the address part from the native crash message.
    E.g., "ERROR: AddressSanitizer: heap-use-after-free on address 0x7f... at pc 0x7f..."
    becomes "ERROR: AddressSanitizer: heap-use-after-free on address <ADDR> at pc <ADDR>".
    """
    pattern = r"\b0x[0-9a-fA-F]+\b"
    return re.sub(pattern, "<ADDR>", crash).strip()


def _parse_crash_line(line: str, initial_timestamp: Optional[int]) -> Optional[Tuple]:
    match = LIBFUZZER_CRASH_LINE_PTRN.match(line)
    if match:
        timestamp, crash = int(match.group(1)), match.group(2)
        elapsed_time = (
            timestamp - initial_timestamp if initial_timestamp is not None else None
        )
        return elapsed_time, crash
    match = LIBFUZZER_NATIVE_CRASH_LINE_PTRN.match(line)
    if match:
        timestamp, crash = int(match.group(1)), match.group(2)
        elapsed_time = (
            timestamp - initial_timestamp if initial_timestamp is not None else None
        )
        crash = _replace_hex_addr(crash)
        return elapsed_time, crash
    match = OLD_LIBFUZZER_CRASH_LINE_PTRN.match(line)
    if match:
        crash = match.group(1)
        return None, crash
    match = OLD_LIBFUZZER_NATIVE_CRASH_LINE_PTRN.match(line)
    if match:
        crash = match.group(1)
        crash = _replace_hex_addr(crash)
        return None, crash
    return None


def _parse_stack_frame_line(
    line: str, initial_timestamp: Optional[int]
) -> Optional[Tuple]:
    match = LIBFUZZER_CRASH_STACK_LINE_PTRN.match(line)
    if match:
        timestamp, frame = int(match.group(1)), match.group(2)
        elapsed_time = (
            timestamp - initial_timestamp if initial_timestamp is not None else None
        )
        return elapsed_time, frame
    else:
        match = OLD_LIBFUZZER_CRASH_STACK_LINE_PTRN.match(line)
        if match:
            frame = match.group(1)
            return None, frame
    return None


def _parse_dedup_crash_token_line(
    line: str, initial_timestamp: Optional[int]
) -> Optional[Tuple]:
    match = LIBFUZZER_DEDUP_CRASH_TOKEN.match(line)
    if match:
        timestamp, dedup_token = int(match.group(1)), match.group(2)
        elapsed_time = (
            timestamp - initial_timestamp if initial_timestamp is not None else None
        )
        return elapsed_time, dedup_token
    else:
        match = OLD_LIBFUZZER_DEDUP_CRASH_TOKEN.match(line)
        if match:
            dedup_token = match.group(1)
            return None, dedup_token
    return None


def _parse_artifact_line(
    line: str, initial_timestamp: Optional[int]
) -> Optional[Tuple]:
    global is_libafl_jazzer

    # Define patterns based on mode
    if is_libafl_jazzer:
        patterns_with_timestamp = [LIBAFL_JAZZER_CRASH_ARTIFACT_LINE_PTRN]
        patterns_without_timestamp = []
    else:
        patterns_with_timestamp = [
            CRASH_ARTIFACT_LINE_PTRN,
            CRASH_REPRO_ARTIFACT_LINE_PTRN
        ]
        patterns_without_timestamp = [
            OLD_CRASH_ARTIFACT_LINE_PTRN,
            OLD_CRASH_REPRO_ARTIFACT_LINE_PTRN
        ]

    # Check patterns with timestamp (groups 1 and 2)
    for pattern in patterns_with_timestamp:
        match = pattern.match(line)
        if match:
            timestamp, artifact = int(match.group(1)), match.group(2)
            elapsed_time = (
                timestamp - initial_timestamp if initial_timestamp is not None else None
            )
            return elapsed_time, artifact

    # Check patterns without timestamp (only group 1)
    for pattern in patterns_without_timestamp:
        match = pattern.match(line)
        if match:
            artifact = match.group(1)
            return None, artifact

        return None


def _parse_beep_coord_line(
    line: str, initial_timestamp: Optional[int]
) -> Optional[Tuple]:
    match = BEEP_COORD_LINE_PTRN.match(line)
    if match:
        timestamp, coord = int(match.group(1)), match.group(2)
        elapsed_time = (
            timestamp - initial_timestamp if initial_timestamp is not None else None
        )
        return elapsed_time, coord
    else:
        match = OLD_BEEP_COORD_LINE_PTRN.match(line)
        if match:
            coord = match.group(1)
            return None, coord
    return None


def parse_log_in_stream(
    file_obj, fuzz_data: dict, dump_fuzz_data_fn=None, no_tee=False, log_file=None
):
    """
    Parses all fuzz status lines from libfuzzer logs using streaming.
    - fuzz_data is a dict that will be updated with the parsed data.
    - if no_tee is True, do not output the stdin line to stdout.
    - if log_file is provided, logs will be written to the file with rolling behavior
    """
    global is_libafl_jazzer, logger, keep_full_detail, artifact_dir

    # Set up logger if not already configured
    if logger is None:
        setup_logger(log_file)

    cov_over_time = []
    ft_over_time = []
    rss_over_time = []
    log_crash_over_time = []
    artifact_over_time = []
    log_dedup_crash_over_time = []
    beep_coord_over_time = []

    pending_crash = None
    seen_dedup_tokens = set()
    seen_nonsec_crash_exps = set()
    seen_beep_coords = set()

    ttl_round = 0
    last_cov, last_ft, last_rss = 0, 0, 0
    max_cov, max_ft, max_rss = 0, 0, 0
    ttl_beep_coord = 0
    ttl_restart = 0

    need_dump = False

    def sync_result(data: dict):
        global FALL_THROUGH_THRESHOLD

        data.update(
            {
                "log_dedup_crash_over_time": log_dedup_crash_over_time,
                "ttl_round": ttl_round,
                "last_cov": last_cov,
                "last_ft": last_ft,
                "last_rss": last_rss,
                "max_cov": max_cov,
                "max_ft": max_ft,
                "max_rss": max_rss,
                "ttl_beep_coord": ttl_beep_coord,
                "ttl_restart": ttl_restart,
            }
        )
        if (
            data.get("do_fall_through", False) is False
            and ttl_restart > FALL_THROUGH_THRESHOLD
            and max_cov == 0
            and max_ft == 0
            and ttl_round == 0
        ):
            logger.warning(
                f"[JAZZER_LOG_PARSER] {CRS_WARN} no cov/ft/exec info at all after {ttl_restart} restarts, "
                "this may indicate a problem with the fuzzing setup, fall through to naive fuzzer."
            )
            data["do_fall_through"] = True
        if keep_full_detail:
            data.update(
                {
                    "cov_over_time": cov_over_time,
                    "ft_over_time": ft_over_time,
                    "rss_over_time": rss_over_time,
                    "log_crash_over_time": log_crash_over_time,
                    "artifact_over_time": artifact_over_time,
                    "beep_coord_over_time": beep_coord_over_time,
                }
            )

    try:
        initial_timestamp = None
        ttl_roundno_base = 0
        last_dump_time = time.time()

        # fuzz_statuses & all_fuzz_statuses are kept for potential future use
        all_fuzz_statuses = []
        fuzz_statuses = []

        for line in file_obj:
            try:
                # Skip the line which we cannot decode
                decoded_line = line.decode("utf-8", errors="ignore").strip()

                # Log the line to our configured logger
                if not no_tee:
                    logger.info(decoded_line)

            except UnicodeDecodeError as e:
                logger.warning(
                    f"[JAZZER_LOG_PARSER] {CRS_WARN} decoding line {line}: {e}"
                )
                continue

            # Only one of the following case will match for each line

            # 1. fuzzer start line: initial timestamp
            if initial_timestamp is None:
                match = FUZZ_START_LINE_PTRN.match(decoded_line)
                if match:
                    initial_timestamp = int(match.group(1))
                    need_dump = True  # We need to dump data when start line is found

            if not is_libafl_jazzer and is_libafl_jazzer_flag_line(decoded_line):
                is_libafl_jazzer = True

            # 2. cov line: cov, ft, rss, roundno, timestamp
            rslt = _parse_cov_line(decoded_line, initial_timestamp)
            if rslt:
                roundno, elapsed_time, cov, ft, rss = rslt
                last_cov, max_cov = cov, max(max_cov, cov)
                last_ft, max_ft = ft, max(max_ft, ft)
                last_rss, max_rss = rss, max(max_rss, rss)
                if keep_full_detail:
                    cov_over_time.append((elapsed_time, cov))
                    ft_over_time.append((elapsed_time, ft))
                    rss_over_time.append((elapsed_time, rss))
                ttl_round = ttl_roundno_base + roundno

                fuzz_statuses.append((roundno, elapsed_time, cov, ft, rss))

            # 3. crash line: crash, timestamp
            rslt = _parse_crash_line(decoded_line, initial_timestamp)
            if rslt:
                elapsed_time, crash = rslt
                if keep_full_detail:
                    log_crash_over_time.append((elapsed_time, crash))

                sanitizer = crash_2_sanitizer(crash)
                pending_crash = [elapsed_time, crash, sanitizer, [], None]

            if pending_crash is not None:
                # crash stack frame line
                rslt = _parse_stack_frame_line(decoded_line, initial_timestamp)
                if rslt:
                    _, frame = rslt
                    pending_crash[3].append(frame)

                # crash dedup token line
                rslt = _parse_dedup_crash_token_line(decoded_line, initial_timestamp)
                if rslt:
                    _, crash_token = rslt
                    pending_crash[4] = crash_token

            # 4. artifact line: artifact, timestamp
            rslt = _parse_artifact_line(decoded_line, initial_timestamp)
            if rslt:
                elapsed_time, artifact = rslt
                if keep_full_detail:
                    artifact_over_time.append((elapsed_time, artifact))

                if pending_crash is not None:
                    crash_time, crash, sanitizer, frames, dedup_token = pending_crash
                    if dedup_token is None or dedup_token not in seen_dedup_tokens:
                        if (
                            not sanitizer.startswith("NONSEC-")
                            or sanitizer not in seen_nonsec_crash_exps
                        ):
                            log_dedup_crash_over_time.append(
                                (
                                    crash_time,
                                    sanitizer,
                                    crash,
                                    frames,
                                    dedup_token,
                                    artifact,
                                )
                            )

                            seen_dedup_tokens.add(dedup_token)
                            if sanitizer.startswith("NONSEC-"):
                                seen_nonsec_crash_exps.add(sanitizer)
                            need_dump = True  # Dump data when new artifact is triaged
                    pending_crash = None

                    if (
                        artifact_dir is not None
                        and keep_full_detail is False
                        and sanitizer.startswith("NONSEC-")
                        and need_dump is False
                        and dedup_token is not None
                        and dedup_token not in seen_dedup_tokens
                        and len(seen_nonsec_crash_exps) > 100000
                    ):
                        try:
                            artifact_file = os.path.join(artifact_dir, artifact)
                            os.remove(artifact_file)
                            logger.info(
                                f"[JAZZER_LOG_PARSER] removed not reported artifact {sanitizer} {need_dump} {artifact_file}"
                            )
                        except Exception:
                            pass

                elif artifact.startswith("timeout-"):
                    # Timeout artifact
                    log_dedup_crash_over_time.append(
                        (
                            elapsed_time,  # crash_time
                            "timeout",  # sanitizer
                            "Jazzer timeout",  # crash
                            [],  # frames
                            "timeout-fake-dedup-token",  # dedup_token
                            artifact,  # artifact
                        )
                    )
                    seen_dedup_tokens.add("timeout-fake-dedup-token")
                    seen_nonsec_crash_exps.add("timeout")
                    need_dump = True

            # 5. beep coordinate line: beep coordinate
            rslt = _parse_beep_coord_line(decoded_line, initial_timestamp)
            if rslt:
                elapsed_time, coord = rslt
                seen_beep_coords.add(coord)
                ttl_beep_coord = len(seen_beep_coords)
                if keep_full_detail:
                    beep_coord_over_time.append((elapsed_time, coord))

            # 6. exit line: exit log
            if JAZZER_EXIT_LOG in decoded_line:
                ttl_roundno_base = ttl_round

                if len(fuzz_statuses) > 0:
                    all_fuzz_statuses.append(fuzz_statuses)
                    fuzz_statuses = []
                ttl_restart += 1
                need_dump = True

            sync_result(fuzz_data)

            current_time = time.time()
            if need_dump or (current_time - last_dump_time >= 180):  # 3 min
                if dump_fuzz_data_fn is not None:
                    dump_fuzz_data_fn()
                need_dump = False
                last_dump_time = current_time

        if len(fuzz_statuses) > 0:
            all_fuzz_statuses.append(fuzz_statuses)

    except Exception as e:
        logger.error(f"[JAZZER_LOG_PARSER] {CRS_ERR} parsing libFuzzer logs: {e}")


def parse_libfuzzer_log(
    log_file: str,
    fuzz_data: dict = None,
    dump_fuzz_data_fn=None,
    no_tee=False,
    rolling_log_file=None,
) -> dict:
    """
    Parse fuzz_data from libFuzzer log file.
    - if fuzz_data is provided, it will be updated with the parsed data.
    - if fuzz_data is None, a new dict will be created and returned.
    - if no_tee is True, do not output the stdin line to stdout.
    - if rolling_log_file is provided, output is saved to this file with rolling behavior
    """
    global logger

    # Set up logger if not already configured
    if logger is None:
        setup_logger(rolling_log_file)

    _fuzz_data = fuzz_data if fuzz_data is not None else {}

    try:
        with open(log_file, "rb") as file_obj:
            parse_log_in_stream(
                file_obj,
                fuzz_data=_fuzz_data,
                dump_fuzz_data_fn=dump_fuzz_data_fn,
                no_tee=no_tee,
                log_file=rolling_log_file,
            )

    except Exception as e:
        logger.error(
            f"[JAZZER_LOG_PARSER] {CRS_ERR} parsing libFuzzer log file {log_file}: {e}"
        )

    return _fuzz_data


def main():
    """
    Main function to handle CLI arguments and run the parsing process.
    Wrapped in a function to better handle exceptions.
    """
    parser = argparse.ArgumentParser(
        description="Analyze fuzzing data and output JSON results."
    )
    parser.add_argument(
        "fuzz_log_file",
        nargs="?",
        help="Path to the file containing fuzz data (fuzz.log).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to the output file where JSON results will be saved.",
        default=None,
    )
    parser.add_argument(
        "--no-tee",
        action="store_true",
        help="Do not output the stdin line to stdout (disable tee behavior).",
    )
    parser.add_argument(
        "--rolling-log",
        help="Path to the rolling log file (max size 1GB, no backup).",
        default=None,
    )

    args = parser.parse_args()

    # Set up the rolling logger if specified
    if args.rolling_log:
        setup_logger(args.rolling_log)
    else:
        setup_logger(None)  # Use stdout by default

    out_obj = {}
    if args.output and os.path.exists(args.output):
        try:
            with open(args.output) as f:
                out_obj = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing output file: {e}")
            out_obj = {}

    fuzz_data = {}

    def dump_fuzz_data():
        nonlocal fuzz_data

        if args.output:
            out_obj["fuzz_data"] = fuzz_data
            try:
                output_path = Path(args.output)
                temp_path = output_path.parent / f".hidden.{output_path.name}"

                with open(temp_path, "w") as f:
                    json.dump(out_obj, f, indent=2)

                # Atomically update the output file
                os.replace(temp_path, output_path)
            except Exception as e:
                logger.error(f"Error writing output file: {e}")
        else:
            logger.info(json.dumps({"fuzz_data": fuzz_data}, indent=2))

    def signal_handler(sig, frame):
        """
        Gracefully exit the script.
        """
        logger.info("[JAZZER_LOG_PARSER] Exiting...")
        dump_fuzz_data()
        sys.exit(0)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGPIPE, signal_handler)

    # Determine if input is from stdin or a file
    if not sys.stdin.isatty():
        # Input is from stdin (piped input)
        logger.info("[JAZZER_LOG_PARSER] Analyzing fuzz data from stream...")
        parse_log_in_stream(
            sys.stdin.buffer,
            fuzz_data=fuzz_data,
            dump_fuzz_data_fn=dump_fuzz_data,
            no_tee=args.no_tee,
            log_file=args.rolling_log,
        )
        dump_fuzz_data()

    elif args.fuzz_log_file:
        # Input is a fuzz log file
        parse_libfuzzer_log(
            args.fuzz_log_file,
            fuzz_data=fuzz_data,
            dump_fuzz_data_fn=dump_fuzz_data,
            no_tee=args.no_tee,
            rolling_log_file=args.rolling_log,
        )
        dump_fuzz_data()

    else:
        logger.info("[JAZZER_LOG_PARSER] Usage:")
        logger.info(
            "[JAZZER_LOG_PARSER]   python this_script.py [fuzz_log_file] [-o output_file] [--rolling-log log_file]"
        )
        logger.info("[JAZZER_LOG_PARSER] Or pipe the log data to the script:")
        logger.info(
            "[JAZZER_LOG_PARSER]   fuzz_command | python this_script.py [-o output_file] [--rolling-log log_file]"
        )
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Ensure the logger is set up in case of early exceptions
        if logger is None:
            setup_logger(None)  # Default to stdout
        logger.error(f"[JAZZER_LOG_PARSER] Unhandled exception: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
