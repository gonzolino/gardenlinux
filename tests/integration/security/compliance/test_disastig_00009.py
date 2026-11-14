"""
Ref: SRG-OS-000028-GPOS-00009

Verify the operating system retains a user's session lock until that user reestablishes access using established identification and authentication procedures.
"""

import pytest


@pytest.mark.security_id(203598)
# Fork note (kvm-capi fork): also skip for capi flavors — the capi element
# excludes the _selinux feature, so 'selinux' never appears in the LSM list.
# Upstream's near-identical sibling test (disastig_00155) already gates on
# "not capi"; this one was missed because upstream capi flavors are masked by
# "not baremetal" anyway.
@pytest.mark.feature(
    "not container and not lima and not gardener and not baremetal and not capi"
)
@pytest.mark.root(reason="required to verify PAM authentication enforcement")
def test_session_lock_requires_reauthentication(lsm):
    """Verify 'selinux' appears in the active LSM list."""
    assert (
        "selinux" in lsm
    ), "stigcompliance: no LSM (AppArmor/SELinux) present to enforce session lock re-authentication"
