import unittest

from experiment import build_benchmark_record


class BenchmarkRecordTests(unittest.TestCase):
    def test_record_includes_reproduction_metadata(self):
        results = [{"name": "ML-KEM-768", "keygen_ms": 1.25}]
        environment = {
            "python": "3.12.7",
            "platform": "test-platform",
            "dependencies": {"cryptography": "43.0.0"},
        }

        record = build_benchmark_record(
            results,
            iterations=30,
            generated_at="2026-09-23T12:00:00Z",
            environment=environment,
        )

        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["generated_at"], "2026-09-23T12:00:00Z")
        self.assertEqual(record["experiment"]["iterations_per_algorithm"], 30)
        self.assertEqual(record["environment"], environment)
        self.assertEqual(record["results"], results)


if __name__ == "__main__":
    unittest.main()
