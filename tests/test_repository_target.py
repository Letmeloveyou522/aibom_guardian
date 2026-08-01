"""
tests/test_repository_target.py
-----------------------------------
Tests for check_repository's named-part arguments.

    python3 -m pytest tests/test_repository_target.py -q

The single-string form ("requests==2.28.0") is easy to build wrong, and
"owner/repo" alone is ambiguous between GitHub and Hugging Face. The named
forms settle both. The positional form is unchanged, so the existing 39
tests and the MCP tool keep working.

No network: only the argument resolution is under test.
"""

import pytest

from repository_checker import _resolve_target


def resolve(target=None, target_type="auto", **kw):
    return _resolve_target(target, target_type, **kw)


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

def test_positional_target_is_unchanged():
    assert resolve("requests==2.28.0") == ("requests==2.28.0", "auto")


def test_positional_target_keeps_an_explicit_type():
    assert resolve("pallets/flask", "github") == ("pallets/flask", "github")


def test_positional_target_wins_over_named_parts():
    """Existing callers must not change behaviour if they pass both."""
    assert resolve("explicit/target", package_name="ignored")[0] == "explicit/target"


# ---------------------------------------------------------------------------
# Named forms
# ---------------------------------------------------------------------------

def test_package_name_and_version():
    assert resolve(package_name="requests", version="2.28.0") == (
        "requests==2.28.0", "pypi")


def test_package_name_without_version():
    assert resolve(package_name="requests") == ("requests", "pypi")


def test_owner_and_repo_resolve_to_github():
    """
    'owner/repo' on its own could be GitHub or Hugging Face. Naming the
    parts settles it, so the caller need not remember target_type.
    """
    assert resolve(owner="pallets", repo="flask") == ("pallets/flask", "github")


def test_dataset_id_resolves_to_hf_dataset():
    assert resolve(dataset_id="squad") == ("squad", "hf_dataset")


@pytest.mark.parametrize("kwargs,explicit", [
    ({"package_name": "requests"}, "local"),
    ({"owner": "a", "repo": "b"}, "hf_model"),
    ({"dataset_id": "squad"}, "github"),
])
def test_explicit_target_type_overrides_the_inferred_one(kwargs, explicit):
    assert resolve(target_type=explicit, **kwargs)[1] == explicit


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

def test_no_target_at_all_raises():
    with pytest.raises(ValueError, match="needs a target"):
        resolve()


def test_owner_without_repo_raises():
    """Half a repository reference is not a target."""
    with pytest.raises(ValueError):
        resolve(owner="pallets")


def test_empty_string_target_falls_through_to_named_parts():
    assert resolve("", package_name="requests") == ("requests", "pypi")
