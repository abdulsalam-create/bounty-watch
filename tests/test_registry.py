import pytest

from bounty_watch import PROGRAMS, get_program, search_targets


def test_known_programs_and_metadata():
    assert [p.key for p in PROGRAMS] == ["bc:afterpay", "bc:lululemon", "bc:tidal-bugbounty"]
    assert get_program("bc:afterpay").bounty_usd == 5000
    assert get_program("bc:lululemon").url.endswith("/lululemon")


def test_targets_preserve_wildcards_apps_and_urls():
    assert "*.lululemon.com" in get_program("bc:lululemon").target_values
    assert get_program("bc:lululemon").targets[0].is_wildcard
    assert "Tidal Client for Android" in get_program("bc:tidal-bugbounty").target_values
    assert not get_program("bc:afterpay").targets[0].is_wildcard


def test_search_is_case_insensitive_and_handles_blank():
    matches = search_targets("https://api.clearpay.com")
    assert [(p.key, t.value) for p, t in matches] == [("bc:afterpay", "https://api.clearpay.com")]
    assert any(t.value == "Tidal Client for iOS" for _, t in search_targets("ios"))
    assert search_targets("   ") == ()


def test_unknown_program_is_explicit():
    with pytest.raises(KeyError, match="unknown program"):
        get_program("bc:missing")


def test_every_program_has_valid_minimum_metadata():
    assert all(p.key.startswith("bc:") and p.bounty_usd > 0 and p.targets for p in PROGRAMS)
