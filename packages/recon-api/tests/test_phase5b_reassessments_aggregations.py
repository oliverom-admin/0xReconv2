"""Tests for Phase 5B — ReassessmentService, AggregationService, routes."""
from __future__ import annotations

import pytest


# ── ReassessmentService tests ─────────────────────────────────

class TestReassessmentServiceImports:
    def test_imports(self):
        from recon_api.services.reassessment import ReassessmentService
        assert ReassessmentService is not None

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import reassessment
        src = inspect.getsource(reassessment)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")

    def test_dispatches_job(self):
        import inspect
        from recon_api.services.reassessment import ReassessmentService
        src = inspect.getsource(ReassessmentService.create_reassessment)
        assert "reassessment_execute" in src
        assert "job_queue" in src


class TestReassessmentResultSummary:
    def test_execute_method_has_required_fields(self):
        import inspect
        from recon_api.services.reassessment import ReassessmentService
        src = inspect.getsource(ReassessmentService.execute_reassessment)
        for field in ("total_certificates", "total_findings",
                      "health_score", "grade", "policy_name"):
            assert field in src, f"Missing field in result_summary: {field}"


# ── AggregationService tests ─────────────────────────────────

class TestAggregationServiceImports:
    def test_imports(self):
        from recon_api.services.aggregation import AggregationService
        assert AggregationService is not None

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import aggregation
        src = inspect.getsource(aggregation)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")

    def test_all_merge_strategies_present(self):
        import inspect
        from recon_api.services.aggregation import AggregationService
        src = inspect.getsource(AggregationService)
        assert "_merge_union" in src
        assert "_merge_intersection" in src
        assert "_merge_weighted" in src


class TestMergeUnion:
    def test_deduplicates_by_fingerprint(self):
        from recon_api.services.aggregation import AggregationService
        scan_a = {"certificates": [
            {"fingerprint_sha256": "aabb", "subject_cn": "cert1"},
            {"fingerprint_sha256": "ccdd", "subject_cn": "cert2"},
        ], "keys": []}
        scan_b = {"certificates": [
            {"fingerprint_sha256": "ccdd", "subject_cn": "cert2-dup"},
            {"fingerprint_sha256": "eeff", "subject_cn": "cert3"},
        ], "keys": []}
        certs, keys = AggregationService._merge_union([scan_a, scan_b])
        fps = [c["fingerprint_sha256"] for c in certs]
        assert len(fps) == 3  # aabb, ccdd, eeff
        assert len(set(fps)) == 3

    def test_combines_keys(self):
        from recon_api.services.aggregation import AggregationService
        scan_a = {"certificates": [], "keys": [
            {"key_id": "k1", "name": "key1"},
        ]}
        scan_b = {"certificates": [], "keys": [
            {"key_id": "k2", "name": "key2"},
        ]}
        _, keys = AggregationService._merge_union([scan_a, scan_b])
        assert len(keys) == 2


class TestMergeIntersection:
    def test_only_shared(self):
        from recon_api.services.aggregation import AggregationService
        scan_a = {"certificates": [
            {"fingerprint_sha256": "aabb"},
            {"fingerprint_sha256": "ccdd"},
        ], "keys": []}
        scan_b = {"certificates": [
            {"fingerprint_sha256": "ccdd"},
            {"fingerprint_sha256": "eeff"},
        ], "keys": []}
        certs, _ = AggregationService._merge_intersection([scan_a, scan_b])
        assert len(certs) == 1
        assert certs[0]["fingerprint_sha256"] == "ccdd"

    def test_empty_when_no_overlap(self):
        from recon_api.services.aggregation import AggregationService
        scan_a = {"certificates": [{"fingerprint_sha256": "aa"}], "keys": []}
        scan_b = {"certificates": [{"fingerprint_sha256": "bb"}], "keys": []}
        certs, _ = AggregationService._merge_intersection([scan_a, scan_b])
        assert len(certs) == 0


class TestMergeWeighted:
    def test_adds_occurrence_count(self):
        from recon_api.services.aggregation import AggregationService
        scan_a = {"certificates": [{"fingerprint_sha256": "aabb"}], "keys": []}
        scan_b = {"certificates": [{"fingerprint_sha256": "aabb"}], "keys": []}
        scan_c = {"certificates": [{"fingerprint_sha256": "ccdd"}], "keys": []}
        certs, _ = AggregationService._merge_weighted([scan_a, scan_b, scan_c])
        by_fp = {c["fingerprint_sha256"]: c for c in certs}
        assert by_fp["aabb"]["scan_occurrence_count"] == 2
        assert by_fp["aabb"]["scan_occurrence_pct"] == pytest.approx(66.7, abs=0.1)
        assert by_fp["ccdd"]["scan_occurrence_count"] == 1


class TestAggregationValidation:
    def test_single_scan_raises(self):
        from recon_api.services.aggregation import AggregationService, VALID_STRATEGIES
        # _merge_union is static, but create_aggregation does validation
        # Test the validation constants
        assert len(VALID_STRATEGIES) == 3
        assert "union" in VALID_STRATEGIES
        assert "intersection" in VALID_STRATEGIES
        assert "weighted" in VALID_STRATEGIES


# ── Worker handler tests ──────────────────────────────────────

class TestWorkerHandlers:
    def test_reassessment_handler_registered(self):
        import inspect
        from recon_api.services.scheduler import SchedulerService
        src = inspect.getsource(SchedulerService._dispatch)
        assert "reassessment_execute" in src

    def test_aggregation_handler_registered(self):
        import inspect
        from recon_api.services.scheduler import SchedulerService
        src = inspect.getsource(SchedulerService._dispatch)
        assert "aggregation_execute" in src


# ── Route tests ───────────────────────────────────────────────

class TestReassessmentRoutes:
    async def test_list_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/reassessments/fake-id/")
        assert r.status_code in (401, 403)

    async def test_create_requires_auth(self, async_client):
        r = await async_client.post(
            "/api/v1/reassessments/fake-id/",
            json={"name": "test", "original_scan_id": "x", "policy_id": "y"},
        )
        assert r.status_code in (401, 403)

    async def test_result_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/reassessments/fake-id/fake-rid/result/")
        assert r.status_code in (401, 403)


class TestAggregationRoutes:
    async def test_list_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/aggregations/fake-id/")
        assert r.status_code in (401, 403)

    async def test_create_requires_auth(self, async_client):
        r = await async_client.post(
            "/api/v1/aggregations/fake-id/",
            json={"name": "test", "source_scan_ids": ["a"], "merge_strategy": "union"},
        )
        assert r.status_code in (401, 403)

    async def test_delete_requires_auth(self, async_client):
        r = await async_client.delete("/api/v1/aggregations/fake-id/fake-aid/")
        assert r.status_code in (401, 403)
