"""Utilities used by report templates."""

from __future__ import annotations

from typing import Any, List


class ReportUtils:
    """Helper methods exposed to Jinja-style templates via :class:`SuperFormatter`."""

    @staticmethod
    def getParentName(element: Any) -> str:
        """Return the parent boundary name for *element* or an empty string."""
        from pytm import Boundary  # Local import to avoid circular dependency

        if not isinstance(element, Boundary):
            return f"ERROR: getParentName method is not valid for {type(element).__name__}"

        parent = element.inBoundary
        return parent.name if parent is not None else ""

    @staticmethod
    def getNamesOfParents(element: Any) -> List[str] | str:
        """Return a list of parent boundary names for *element*."""
        from pytm import Boundary

        if not isinstance(element, Boundary):
            return f"ERROR: getNamesOfParents method is not valid for {type(element).__name__}"

        return [parent.name for parent in element.parents()]

    @staticmethod
    def getFindingCount(element: Any) -> str:
        """Return the count of findings for *element* as a string."""
        from pytm import Element

        if not isinstance(element, Element):
            return f"ERROR: getFindingCount method is not valid for {type(element).__name__}"

        return str(len(list(element.findings)))

    @staticmethod
    def getElementType(element: Any) -> str:
        """Return the class name for *element*."""
        from pytm import Element

        if not isinstance(element, Element):
            return f"ERROR: getElementType method is not valid for {type(element).__name__}"

        return element.__class__.__name__
