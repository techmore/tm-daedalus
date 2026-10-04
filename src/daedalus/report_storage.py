"""Portable workspace-scoped resolution of generated report files."""
from pathlib import Path


def report_artifact(root: Path, organization_id: int, file_name: str) -> Path:
    if type(organization_id) is not int or organization_id <= 0:
        raise ValueError('Invalid report workspace')
    if (not isinstance(file_name, str) or not file_name or len(file_name) > 255
            or '/' in file_name or '\\' in file_name or '\x00' in file_name
            or file_name in {'.', '..'} or not file_name.endswith('.pdf')):
        raise ValueError('Invalid report file name')
    resolved_root = root.resolve(strict=True)
    directory = resolved_root / str(organization_id)
    if directory.is_symlink():
        raise ValueError('Report workspace directory must not be a link')
    resolved_directory = directory.resolve(strict=True)
    if resolved_directory != directory or not resolved_directory.is_dir():
        raise ValueError('Invalid report workspace directory')
    candidate = resolved_directory / file_name
    if candidate.is_symlink():
        raise ValueError('Report artifact must not be a link')
    artifact = candidate.resolve(strict=True)
    if artifact.parent != resolved_directory or not artifact.is_file():
        raise ValueError('Report artifact is outside its workspace')
    return artifact
