"""Typed, immutable-ish registry of the 2026-09-22 in-scope additions.

The source feed is deliberately represented as data: target strings are not
normalised into URLs because Bugcrowd also uses app names and wildcard scopes.
"""
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Target:
    value: str

    @property
    def is_wildcard(self) -> bool:
        return "*" in self.value


@dataclass(frozen=True)
class Program:
    key: str
    name: str
    bounty_usd: int
    url: str
    targets: tuple[Target, ...]

    @property
    def target_values(self) -> tuple[str, ...]:
        return tuple(target.value for target in self.targets)


def _program(key: str, name: str, bounty: int, slug: str, targets: Iterable[str]) -> Program:
    values = tuple(Target(value) for value in targets)
    if not values:
        raise ValueError(f"program {key!r} must have at least one target")
    return Program(key, name, bounty, f"https://bugcrowd.com/engagements/{slug}", values)


PROGRAMS: tuple[Program, ...] = (
    _program("bc:afterpay", "Afterpay Bug Bounty Program", 5000, "afterpay", (
        "https://afterpay.com", "https://api.clearpay.com",
        "https://apps.apple.com/au/app/afterpay-shop-now-pay-later/id1230286588",
        "https://apps.apple.com/gb/app/clearpay-buy-now-pay-later/id1474022186",
        "https://clearpay.co.uk", "https://clearpay.com", "https://developers.afterpay.com",
        "https://mobileapi.afterpay.com", "https://mobileapi.clearpay.com",
        "https://play.google.com/store/apps/details?id=com.afterpaymobile.uk",
        "https://play.google.com/store/apps/details?id=com.afterpaymobile.us&hl=en_US&gl=US",
        "https://portal.afterpay.com", "https://portal.clearpay.co.uk", "https://portal.clearpay.com",
        "https://portalapi.eu.clearpay.co.uk", "https://portalapi.us.afterpay.com",
    )),
    _program("bc:lululemon", "lululemon", 8000, "lululemon", (
        "*.lululemon.com", "http://www.lululemon.co.kr/",
        "https://apps.apple.com/us/app/lululemon/id920098546", "https://shop.lululemon.com",
        "https://www.eu.lululemon.com/", "https://www.lululemon.co.jp/", "https://www.lululemon.co.nz/",
        "https://www.lululemon.co.uk/", "https://www.lululemon.com.au/", "https://www.lululemon.com.hk/",
        "https://www.lululemon.de/", "https://www.lululemon.es/", "https://www.lululemon.fr/",
    )),
    _program("bc:tidal-bugbounty", "TIDAL", 5000, "tidal-bugbounty", (
        "*.tdl.sh", "*.tidalhifi.com", "*.wimpmusic.com", "*tidalhi.fi",
        "Tidal Client for Android", "Tidal Client for iOS",
        "Tidal Official Clients (e.g. Sonos integration, Tesla integration, etc.)",
        "api.tidal.com", "https://offer.tidal.com/download", "https://tidal.com/",
    )),
)


def get_program(key: str) -> Program:
    """Return a program by exact key, raising a useful error when absent."""
    for program in PROGRAMS:
        if program.key == key:
            return program
    raise KeyError(f"unknown program: {key}")


def search_targets(query: str) -> tuple[tuple[Program, Target], ...]:
    """Case-insensitive substring search over program names and targets."""
    needle = query.strip().casefold()
    if not needle:
        return ()
    return tuple(
        (program, target)
        for program in PROGRAMS
        for target in program.targets
        if needle in program.name.casefold() or needle in target.value.casefold()
    )
