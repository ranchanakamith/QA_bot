"""Loads and validates the scoring and scan configuration."""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).with_name("default.yaml")


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def validate(cfg: dict) -> None:
    cats = set(cfg["categories"])
    for name, weights in cfg["profiles"].items():
        if set(weights) != cats:
            raise ValueError(f"profile '{name}' must list exactly these categories: {sorted(cats)}")
        if abs(sum(weights.values()) - 100) > 1e-6:
            raise ValueError(f"profile '{name}' weights sum to {sum(weights.values())}, expected 100")
    for cat_id, cat in cfg["categories"].items():
        total = sum(c["share"] for c in cat["checks"].values())
        if abs(total - 100) > 1e-6:
            raise ValueError(f"check shares in '{cat_id}' sum to {total}, expected 100")
    mins = [lv["min"] for lv in cfg["levels"]]
    if mins != sorted(mins, reverse=True) or mins[-1] != 0:
        raise ValueError("levels must be listed from highest to lowest and end at min 0")


def load_config(path: str | Path | None = None, overrides: dict | None = None) -> dict:
    with open(DEFAULT_PATH, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if path:
        with open(path, encoding="utf-8") as fh:
            cfg = deep_merge(cfg, yaml.safe_load(fh) or {})
    if overrides:
        cfg = deep_merge(cfg, overrides)
    validate(cfg)
    return cfg
