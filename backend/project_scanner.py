from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


# =========================================================
# CyberLens Local Modules
# =========================================================

try:
    from .code_scanner import scan_code_file
    from .sbom_scanner import scan_dependency_file

except ImportError:
    from code_scanner import scan_code_file
    from sbom_scanner import scan_dependency_file


# =========================================================
# حدود الأمان
# =========================================================

MAX_ARCHIVE_SIZE = 50 * 1024 * 1024

MAX_TOTAL_UNCOMPRESSED_SIZE = 150 * 1024 * 1024

MAX_SINGLE_FILE_SIZE = 10 * 1024 * 1024

MAX_ARCHIVE_ENTRIES = 2500

MAX_COMPRESSION_RATIO = 250.0

MAX_CODE_FILES = 300

MAX_DEPENDENCY_FILES = 20

MAX_CODE_FILE_SIZE = 2 * 1024 * 1024


# =========================================================
# الملفات المدعومة
# =========================================================

CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".php",
    ".java",
    ".html",
    ".htm",
    ".css",
    ".sql",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".sh",
    ".ps1",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
}


DEPENDENCY_FILE_NAMES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "composer.lock",
    "go.mod",
    "cargo.lock",
}


# =========================================================
# مجلدات نتجاهلها
# =========================================================

IGNORED_DIRECTORIES = {
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "pycache",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "dist",
    "build",
    "coverage",
    "vendor",
    "target",
}


# =========================================================
# إنشاء Finding خاص بفحص المشروع
# =========================================================

def make_project_finding(
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    **extra: Any,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "source": "CyberLens Project Scanner",
        "confidence": "high",
        "metadata": {},
    }

    finding.update(
        extra
    )

    return finding


# =========================================================
# التحقق من اسم ZIP
# =========================================================

def validate_archive_path(
    archive_path: Path,
) -> None:
    if not archive_path.exists():
        raise ValueError(
            "ملف المشروع غير موجود."
        )

    if not archive_path.is_file():
        raise ValueError(
            "المسار المحدد ليس ملفًا."
        )

    if archive_path.suffix.lower() != ".zip":
        raise ValueError(
            "فحص المشروع يدعم ملفات ZIP فقط."
        )

    archive_size = archive_path.stat().st_size

    if archive_size <= 0:
        raise ValueError(
            "ملف ZIP فارغ."
        )

    if archive_size > MAX_ARCHIVE_SIZE:
        raise ValueError(
            "حجم ملف ZIP يتجاوز الحد المسموح."
        )

    if not zipfile.is_zipfile(
        archive_path
    ):
        raise ValueError(
            "الملف المرفوع ليس ZIP صالحًا."
        )


# =========================================================
# فحص المسار داخل ZIP
# =========================================================

def normalize_zip_member_name(
    raw_name: str,
) -> str:
    value = str(
        raw_name or ""
    ).replace(
        "\\",
        "/",
    ).strip()

    if not value:
        raise ValueError(
            "تم اكتشاف مسار فارغ داخل ZIP."
        )
    if value.startswith(
        "/"
    ):
        raise ValueError(
            "تم اكتشاف مسار مطلق غير آمن داخل ZIP."
        )

    if re.match(
        r"^[A-Za-z]:",
        value,
    ):
        raise ValueError(
            "تم اكتشاف مسار Windows مطلق داخل ZIP."
        )

    pure_path = PurePosixPath(
        value
    )

    if ".." in pure_path.parts:
        raise ValueError(
            "تم اكتشاف محاولة Path Traversal داخل ZIP."
        )

    return pure_path.as_posix()


# =========================================================
# التحقق من أن الهدف داخل مجلد الاستخراج
# =========================================================

def safe_destination_path(
    extraction_root: Path,
    member_name: str,
) -> Path:
    normalized_name = normalize_zip_member_name(
        member_name
    )

    destination = (
        extraction_root
        / Path(
            *PurePosixPath(
                normalized_name
            ).parts
        )
    )

    root_resolved = extraction_root.resolve()

    destination_resolved = destination.resolve(
        strict=False
    )

    try:
        common_path = os.path.commonpath(
            [
                str(root_resolved),
                str(destination_resolved),
            ]
        )

    except ValueError as exc:
        raise ValueError(
            "تم اكتشاف مسار غير آمن داخل ZIP."
        ) from exc

    if common_path != str(
        root_resolved
    ):
        raise ValueError(
            "تم منع استخراج ملف خارج مجلد المشروع."
        )

    return destination


# =========================================================
# اكتشاف Symbolic Links
# =========================================================

def zip_entry_is_symlink(
    info: zipfile.ZipInfo,
) -> bool:
    unix_mode = (
        info.external_attr
        >> 16
    )

    return stat.S_ISLNK(
        unix_mode
    )


# =========================================================
# تجاهل المجلدات غير المهمة
# =========================================================

def should_ignore_parts(
    parts: tuple[str, ...],
) -> bool:
    for part in parts:
        if part.lower() in {
            value.lower()
            for value in IGNORED_DIRECTORIES
        }:
            return True

    return False


# =========================================================
# فحص ZIP قبل الاستخراج
# =========================================================

def inspect_zip_safety(
    archive: zipfile.ZipFile,
) -> dict[str, Any]:
    infos = archive.infolist()

    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise ValueError(
            "عدد الملفات داخل ZIP يتجاوز الحد الآمن."
        )

    total_uncompressed = 0

    files_count = 0

    directories_count = 0

    ignored_entries = 0

    for info in infos:
        normalized_name = normalize_zip_member_name(
            info.filename
        )

        pure_path = PurePosixPath(
            normalized_name
        )

        if should_ignore_parts(
            pure_path.parts
        ):
            ignored_entries += 1
            continue

        if info.is_dir():
            directories_count += 1
            continue

        files_count += 1

        if info.flag_bits & 0x1:
            raise ValueError(
                "ZIP يحتوي ملفًا مشفرًا ولا يمكن فحصه بأمان."
            )

        if zip_entry_is_symlink(
            info
        ):
            raise ValueError(
                "ZIP يحتوي Symbolic Link غير مسموح."
            )

        if info.file_size < 0:
            raise ValueError(
                "تم اكتشاف حجم ملف غير صالح داخل ZIP."
            )

        if info.file_size > MAX_SINGLE_FILE_SIZE:
            raise ValueError(
                "ZIP يحتوي ملفًا مفردًا يتجاوز الحد الآمن."
            )

        total_uncompressed += info.file_size

        if (
            total_uncompressed
            > MAX_TOTAL_UNCOMPRESSED_SIZE
        ):
            raise ValueError(
                "الحجم الكلي بعد فك الضغط يتجاوز الحد الآمن."
            )
        if info.file_size > 0:
            if info.compress_size <= 0:
                raise ValueError(
                    "تم اكتشاف نسبة ضغط غير آمنة داخل ZIP."
                )

            compression_ratio = (
                info.file_size
                / info.compress_size
            )

            if (
                info.file_size
                >= 1024 * 1024
                and compression_ratio
                > MAX_COMPRESSION_RATIO
            ):
                raise ValueError(
                    "تم اكتشاف نمط ضغط قد يشير إلى ZIP Bomb."
                )

    return {
        "entries": len(
            infos
        ),
        "files": files_count,
        "directories": directories_count,
        "ignored_entries": ignored_entries,
        "total_uncompressed_size": total_uncompressed,
    }


# =========================================================
# استخراج ZIP يدويًا وبأمان
# =========================================================

def extract_zip_safely(
    archive_path: Path,
    extraction_root: Path,
) -> dict[str, Any]:
    extracted_files = 0

    skipped_entries = 0

    with zipfile.ZipFile(
        archive_path,
        "r",
    ) as archive:

        safety_report = inspect_zip_safety(
            archive
        )

        for info in archive.infolist():
            normalized_name = normalize_zip_member_name(
                info.filename
            )

            pure_path = PurePosixPath(
                normalized_name
            )

            if should_ignore_parts(
                pure_path.parts
            ):
                skipped_entries += 1
                continue

            destination = safe_destination_path(
                extraction_root,
                normalized_name,
            )

            if info.is_dir():
                destination.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                continue

            if info.flag_bits & 0x1:
                raise ValueError(
                    "تم منع استخراج ملف مشفر."
                )

            if zip_entry_is_symlink(
                info
            ):
                raise ValueError(
                    "تم منع استخراج Symbolic Link."
                )

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            bytes_written = 0

            with archive.open(
                info,
                "r",
            ) as source:

                with destination.open(
                    "wb"
                ) as target:

                    while True:
                        chunk = source.read(
                            1024 * 1024
                        )

                        if not chunk:
                            break

                        bytes_written += len(
                            chunk
                        )

                        if (
                            bytes_written
                            > MAX_SINGLE_FILE_SIZE
                        ):
                            raise ValueError(
                                "تجاوز ملف مستخرج الحد الآمن."
                            )

                        target.write(
                            chunk
                        )

            extracted_files += 1

    return {
        **safety_report,
        "extracted_files": extracted_files,
        "skipped_entries": skipped_entries,
    }


# =========================================================
# نسخ Finding وإضافة مسار المشروع
# =========================================================

def attach_project_context(
    finding: dict[str, Any],
    relative_path: str,
    scanner_type: str,
) -> dict[str, Any]:
    item = dict(
        finding
    )

    metadata = item.get(
        "metadata"
    )

    if isinstance(
        metadata,
        dict,
    ):
        clean_metadata = dict(
            metadata
        )

    else:
        clean_metadata = {}
        clean_metadata[
        "project_file"
    ] = relative_path

    clean_metadata[
        "project_scanner_type"
    ] = scanner_type

    item[
        "metadata"
    ] = clean_metadata

    item[
        "project_file"
    ] = relative_path

    return item


# =========================================================
# اكتشاف ملفات المشروع
# =========================================================

def discover_project_files(
    extraction_root: Path,
) -> dict[str, list[Path]]:
    code_files: list[
        Path
    ] = []

    dependency_files: list[
        Path
    ] = []

    other_files: list[
        Path
    ] = []

    for path in sorted(
        extraction_root.rglob(
            "*"
        )
    ):
        if not path.is_file():
            continue

        try:
            relative = path.relative_to(
                extraction_root
            )

        except ValueError:
            continue

        if should_ignore_parts(
            relative.parts
        ):
            continue

        lower_name = path.name.lower()

        if (
            lower_name
            in DEPENDENCY_FILE_NAMES
        ):
            dependency_files.append(
                path
            )

            continue

        if (
            path.suffix.lower()
            in CODE_EXTENSIONS
        ):
            code_files.append(
                path
            )

            continue

        other_files.append(
            path
        )

    return {
        "code_files": code_files,
        "dependency_files": dependency_files,
        "other_files": other_files,
    }


# =========================================================
# فحص ملفات الكود
# =========================================================

def scan_project_code_files(
    extraction_root: Path,
    code_files: list[Path],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    findings: list[
        dict[str, Any]
    ] = []

    errors: list[
        dict[str, Any]
    ] = []

    for path in code_files[
        :MAX_CODE_FILES
    ]:
        relative_path = path.relative_to(
            extraction_root
        ).as_posix()

        try:
            file_size = path.stat().st_size

            if file_size > MAX_CODE_FILE_SIZE:
                errors.append(
                    {
                        "file": relative_path,
                        "scanner": "code",
                        "error": (
                            "تم تجاوز الملف لأنه أكبر "
                            "من حد فحص الكود."
                        ),
                    }
                )

                continue

            result = scan_code_file(
                path
            )

            raw_findings = result.get(
                "findings",
                [],
            )

            if not isinstance(
                raw_findings,
                list,
            ):
                continue

            for finding in raw_findings:
                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                findings.append(
                    attach_project_context(
                        finding=finding,
                        relative_path=relative_path,
                        scanner_type="code",
                    )
                )

        except Exception as exc:
            errors.append(
                {
                    "file": relative_path,
                    "scanner": "code",
                    "error": str(
                        exc
                    ),
                }
            )

    return (
        findings,
        errors,
    )


# =========================================================
# فحص ملفات الاعتماديات
# =========================================================
def scan_project_dependency_files(
    extraction_root: Path,
    dependency_files: list[Path],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    findings: list[
        dict[str, Any]
    ] = []

    errors: list[
        dict[str, Any]
    ] = []

    scans: list[
        dict[str, Any]
    ] = []

    for path in dependency_files[
        :MAX_DEPENDENCY_FILES
    ]:
        relative_path = path.relative_to(
            extraction_root
        ).as_posix()

        try:
            result = scan_dependency_file(
                path
            )

            raw_findings = result.get(
                "findings",
                [],
            )

            if isinstance(
                raw_findings,
                list,
            ):
                for finding in raw_findings:
                    if not isinstance(
                        finding,
                        dict,
                    ):
                        continue

                    findings.append(
                        attach_project_context(
                            finding=finding,
                            relative_path=relative_path,
                            scanner_type="dependencies",
                        )
                    )

            scans.append(
                {
                    "file": relative_path,
                    "ecosystem": result.get(
                        "ecosystem"
                    ),
                    "packages_scanned": result.get(
                        "packages_scanned",
                        0,
                    ),
                    "queryable_packages": result.get(
                        "queryable_packages",
                        0,
                    ),
                    "total_findings": result.get(
                        "total_findings",
                        0,
                    ),
                    "osv": result.get(
                        "osv",
                        {},
                    ),
                }
            )

        except Exception as exc:
            errors.append(
                {
                    "file": relative_path,
                    "scanner": "dependencies",
                    "error": str(
                        exc
                    ),
                }
            )

    return (
        findings,
        errors,
        scans,
    )


# =========================================================
# إزالة Findings المكررة
# =========================================================

def deduplicate_project_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: list[
        dict[str, Any]
    ] = []

    seen: set[
        tuple[str, str, str]
    ] = set()

    for finding in findings:
        key = (
            str(
                finding.get(
                    "id",
                    "",
                )
            ),
            str(
                finding.get(
                    "project_file",
                    "",
                )
            ),
            str(
                finding.get(
                    "package",
                    "",
                )
            ).lower(),
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        unique.append(
            finding
        )

    return unique


# =========================================================
# الدالة الرئيسية
# =========================================================

def scan_project_archive(
    file_path: str | Path,
) -> dict[str, Any]:
    archive_path = Path(
        file_path
    ).resolve()

    validate_archive_path(
        archive_path
    )

    with tempfile.TemporaryDirectory(
        prefix="cyberlens_project_"
    ) as temp_directory:

        extraction_root = Path(
            temp_directory
        ).resolve()

        extraction_report = extract_zip_safely(
            archive_path=archive_path,
            extraction_root=extraction_root,
        )
        discovered = discover_project_files(
            extraction_root
        )

        code_files = discovered[
            "code_files"
        ]

        dependency_files = discovered[
            "dependency_files"
        ]

        other_files = discovered[
            "other_files"
        ]

        (
            code_findings,
            code_errors,
        ) = scan_project_code_files(
            extraction_root=extraction_root,
            code_files=code_files,
        )

        (
            dependency_findings,
            dependency_errors,
            dependency_scans,
        ) = scan_project_dependency_files(
            extraction_root=extraction_root,
            dependency_files=dependency_files,
        )

        findings = (
            code_findings
            + dependency_findings
        )

        findings = deduplicate_project_findings(
            findings
        )

        errors = (
            code_errors
            + dependency_errors
        )

        scanned_code_files = min(
            len(code_files),
            MAX_CODE_FILES,
        )

        scanned_dependency_files = min(
            len(dependency_files),
            MAX_DEPENDENCY_FILES,
        )

        return {
            "project_name": archive_path.name,

            "archive_type": "zip",

            "findings": findings,

            "total_findings": len(
                findings
            ),

            "files_discovered": (
                len(code_files)
                + len(dependency_files)
                + len(other_files)
            ),

            "code_files_discovered": len(
                code_files
            ),

            "dependency_files_discovered": len(
                dependency_files
            ),

            "other_files_discovered": len(
                other_files
            ),

            "code_files_scanned": (
                scanned_code_files
            ),

            "dependency_files_scanned": (
                scanned_dependency_files
            ),

            "dependency_scans": (
                dependency_scans
            ),

            "errors": errors,

            "total_errors": len(
                errors
            ),

            "extraction": (
                extraction_report
            ),

            "limits": {
                "max_archive_size": (
                    MAX_ARCHIVE_SIZE
                ),
                "max_total_uncompressed_size": (
                    MAX_TOTAL_UNCOMPRESSED_SIZE
                ),
                "max_single_file_size": (
                    MAX_SINGLE_FILE_SIZE
                ),
                "max_archive_entries": (
                    MAX_ARCHIVE_ENTRIES
                ),
                "max_code_files": (
                    MAX_CODE_FILES
                ),
                "max_dependency_files": (
                    MAX_DEPENDENCY_FILES
                ),
            },

            "engine": (
                "CyberLens Safe Project Scanner"
            ),

            "security": {
                "path_traversal_protection": True,
                "absolute_path_protection": True,
                "symlink_protection": True,
                "encrypted_entry_protection": True,
                "zip_bomb_limits": True,
                "temporary_cleanup": True,
                "uploaded_code_execution": False,
            },
        }


# =========================================================
# اختبار مباشر
# =========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("CyberLens Safe Project Scanner")
    print("=" * 60)
    print("Project scanner engine ready.")
    print("ZIP extraction is safety-restricted.")
    print("Uploaded source code is not executed.")
    print("=" * 60)
