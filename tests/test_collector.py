"""Unit tests for the offline collector stub."""

import unittest

from ghorgsec.collector import RealCollectionDisabledError, collect_org_security_snapshot
from ghorgsec.models import ControlState


class CollectorTests(unittest.TestCase):
    def test_offline_stub_marks_controls_as_not_collected(self) -> None:
        snapshot = collect_org_security_snapshot(
            org="example-org",
            repositories=["api", " web ", "api", ""],
        )

        self.assertEqual(snapshot.organization, "example-org")
        self.assertEqual(snapshot.collection_mode, "offline_stub")
        self.assertEqual([repo.name for repo in snapshot.repositories], ["api", "web"])
        self.assertTrue(snapshot.warnings)

        for repository in snapshot.repositories:
            self.assertEqual(repository.branch_protection, ControlState.NOT_COLLECTED)
            self.assertEqual(repository.secret_scanning, ControlState.NOT_COLLECTED)
            self.assertEqual(repository.code_scanning, ControlState.NOT_COLLECTED)
            self.assertEqual(repository.dependabot_alerts, ControlState.NOT_COLLECTED)

    def test_real_collection_is_explicitly_disabled(self) -> None:
        with self.assertRaises(RealCollectionDisabledError):
            collect_org_security_snapshot(
                org="example-org",
                repositories=["api"],
                allow_network=True,
            )

    def test_empty_repository_list_adds_no_rows_warning(self) -> None:
        snapshot = collect_org_security_snapshot(org="  example-org  ", repositories=[])

        self.assertEqual(snapshot.organization, "example-org")
        self.assertEqual(snapshot.repositories, ())
        self.assertTrue(
            any("no rows" in warning for warning in snapshot.warnings),
            msg=f"expected a no-rows warning, got {snapshot.warnings}",
        )

    def test_repository_names_are_normalized_and_deduplicated(self) -> None:
        snapshot = collect_org_security_snapshot(
            org="example-org",
            repositories=["  alpha  ", "alpha", "beta", "", "   "],
        )

        self.assertEqual([repo.name for repo in snapshot.repositories], ["alpha", "beta"])


if __name__ == "__main__":
    unittest.main()

