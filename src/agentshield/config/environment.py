"""Load optional local environment settings for the CLI."""

from __future__ import annotations

from pathlib import Path

from dotenv import find_dotenv, load_dotenv


def load_local_environment(search_directory: Path | None = None) -> bool:
    """Load the nearest .env from a project directory or one of its parents.

    Existing process variables take precedence, so CI and shell configuration
    cannot be silently replaced by a local file.
    """
    if search_directory is None:
        dotenv_path = find_dotenv(usecwd=True)
    else:
        dotenv_path = ""
        for directory in (search_directory, *search_directory.parents):
            candidate = directory / ".env"
            if candidate.is_file():
                dotenv_path = str(candidate)
                break
    if not dotenv_path:
        return False
    return load_dotenv(dotenv_path=dotenv_path, override=False)
