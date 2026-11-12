"""The checks that run in a scan, in pipeline order (read-only checks first)."""
from . import accessibility, compatibility, functional, performance, reliability, security

ALL = [functional.run, security.run, reliability.run, accessibility.run, compatibility.run, performance.run]
