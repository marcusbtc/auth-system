from threading import Lock


class MetricsStore:
    def __init__(self):
        self._lock = Lock()
        self._requests_total = 0
        self._responses_by_status: dict[str, int] = {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0}
        self._latency_sum_ms = 0
        self._latency_count = 0

    def record(self, status_code: int, duration_ms: int) -> None:
        bucket = f'{status_code // 100}xx'
        if bucket not in self._responses_by_status:
            bucket = '5xx'
        with self._lock:
            self._requests_total += 1
            self._responses_by_status[bucket] += 1
            self._latency_sum_ms += duration_ms
            self._latency_count += 1

    def snapshot(self) -> dict:
        with self._lock:
            avg_latency = 0.0
            if self._latency_count > 0:
                avg_latency = round(self._latency_sum_ms / self._latency_count, 2)
            return {
                'requests_total': self._requests_total,
                'responses_by_status': dict(self._responses_by_status),
                'avg_latency_ms': avg_latency,
            }


metrics_store = MetricsStore()
