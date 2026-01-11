"""Resource filtering modules for identifying Packer-related resources.

This module provides the two-criteria filtering system as per Requirements 1.1-1.3:
- TemporalFilter: Age-based filtering using MaxInstanceAge threshold (Requirement 1.1)
- IdentityFilter: Key pair pattern matching for "packer_*" prefix (Requirement 1.2)

Both criteria must match for an instance to be selected for cleanup (Requirement 1.3).
"""

from reaper.filters.base import ResourceFilter
from reaper.filters.identity import IdentityFilter
from reaper.filters.temporal import TemporalFilter

__all__ = ["ResourceFilter", "TemporalFilter", "IdentityFilter"]
