"""
Unit tests for Objective Task Router module.
"""

import unittest
import asyncio
from unittest.mock import AsyncMock, MagicMock

from src.sast.task_router import ObjectiveTaskRouter
from src.sast.routines import default_router

class TestTaskRouter(unittest.TestCase):

    def test_router_registration_and_matching(self):
        router = ObjectiveTaskRouter()

        @router.register_routine(
            name="test_routine",
            keywords=["unit test", "check"],
            description="Sample routine"
        )
        async def dummy_routine(target: str, ctx: dict):
            return {"status": "ok"}

        matched = router.route_instruction("Please run a unit test on target")
        self.assertIn("test_routine", matched)

    def test_execution_dispatch(self):
        async def run_test():
            router = ObjectiveTaskRouter()

            @router.register_routine(
                name="scan_routine",
                keywords=["scan"],
                description="Scan routine"
            )
            async def scan_fn(target: str, ctx: dict):
                return {"target": target, "found": 2}

            result = await router.execute_instruction(
                instruction="Run security scan",
                target_path="./src"
            )

            self.assertEqual(result["instruction"], "Run security scan")
            self.assertIn("scan_routine", result["routines_executed"])
            self.assertEqual(result["results"]["scan_routine"]["found"], 2)

        asyncio.run(run_test())

    def test_default_routines_registration(self):
        routines = default_router.list_routines()
        routine_names = [r["name"] for r in routines]

        self.assertIn("sast_scan", routine_names)
        self.assertIn("stress_test", routine_names)
        self.assertIn("metrics_evaluation", routine_names)

if __name__ == '__main__':
    unittest.main()
