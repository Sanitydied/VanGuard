"""
Unit tests for Phase 1 Alert Queue Manager.
"""

import os
import unittest
from agentndr.alert_queue import AlertQueueManager
from agentndr.traffic_generator import TrafficGenerator, AttackCategory

class TestAlertQueue(unittest.TestCase):
    def setUp(self):
        self.tmp_queue = os.path.join(os.path.dirname(__file__), "test_queue.json")
        self.mgr = AlertQueueManager(queue_filepath=self.tmp_queue)
        self.mgr.clear()

    def tearDown(self):
        if os.path.exists(self.tmp_queue):
            os.remove(self.tmp_queue)

    def test_enqueue_and_persistence(self):
        flow = TrafficGenerator.generate_flow(AttackCategory.PORT_SCAN)
        alert = self.mgr.enqueue_alert(
            flow=flow,
            anomaly_score=0.88,
            path_length=3.5,
            inference_time_ms=0.65
        )
        self.assertTrue(alert.alert_id.startswith("PH1-ALT-"))
        self.assertEqual(len(self.mgr.get_all_alerts()), 1)

        new_mgr = AlertQueueManager(queue_filepath=self.tmp_queue)
        alerts = new_mgr.get_all_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_id, alert.alert_id)
        self.assertEqual(alerts[0].anomaly_score, 0.88)

if __name__ == "__main__":
    unittest.main()
