from charmhelpers.core.hookenv import status_set  # patched

from reactive.calico import pre_series_upgrade


def test_series_upgrade():
    assert status_set.call_count == 0
    pre_series_upgrade()
    assert status_set.call_count == 1
