"""
Exceptions du domaine.

Des exceptions nommées plutôt que des `Exception` génériques : le router
peut les traduire en codes HTTP précis, et les logs disent tout de suite
de quoi il s'agit.
"""


class ScanError(Exception):
    """Erreur de base pour tout ce qui concerne un scan."""


class UnsafeTargetError(ScanError):
    """La cible est interdite (réseau interne, localhost, schéma invalide...)."""


class TargetUnreachableError(ScanError):
    """La cible ne répond pas ou son nom de domaine ne se résout pas."""
