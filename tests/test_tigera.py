from charms.layer import status  # patched

from reactive.calico import pre_series_upgrade


def test_series_upgrade():
    assert status.blocked.call_count == 0
    pre_series_upgrade()
    assert status.blocked.call_count == 1
