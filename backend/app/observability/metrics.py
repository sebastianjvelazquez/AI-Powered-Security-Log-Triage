from __future__ import annotations

from collections import defaultdict
from threading import Lock


def _format_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    parts = [f'{key}="{value}"' for key, value in sorted(labels.items())]
    return "{" + ",".join(parts) + "}"


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._histograms: dict[str, dict[str, object]] = {}

    def increment(self, name: str, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        label_items = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._counters[(name, label_items)] += amount

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        label_items = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._gauges[(name, label_items)] = value

    def observe(
        self,
        name: str,
        value: float,
        *,
        buckets: list[float] | None = None,
        labels: dict[str, str] | None = None,
    ) -> None:
        label_items = tuple(sorted((labels or {}).items()))
        default_buckets = buckets or [0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = {
                    "buckets": sorted(default_buckets),
                    "counts": defaultdict(int),
                    "sums": defaultdict(float),
                    "totals": defaultdict(int),
                }
            histogram = self._histograms[name]
            counts = histogram["counts"]
            sums = histogram["sums"]
            totals = histogram["totals"]
            sums[label_items] += value
            totals[label_items] += 1
            for bucket in histogram["buckets"]:
                if value <= bucket:
                    counts[(label_items, bucket)] += 1

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            for (name, label_items), value in sorted(self._counters.items()):
                lines.append(f"{name}{_format_labels(dict(label_items))} {value}")
            for (name, label_items), value in sorted(self._gauges.items()):
                lines.append(f"{name}{_format_labels(dict(label_items))} {value}")
            for name, histogram in sorted(self._histograms.items()):
                buckets: list[float] = histogram["buckets"]  # type: ignore[assignment]
                counts = histogram["counts"]  # type: ignore[assignment]
                sums = histogram["sums"]  # type: ignore[assignment]
                totals = histogram["totals"]  # type: ignore[assignment]
                label_sets = {label_items for (label_items, _) in counts.keys()} | set(sums.keys()) | set(totals.keys())
                for label_items in sorted(label_sets):
                    for bucket in buckets:
                        bucket_labels = dict(label_items)
                        bucket_labels["le"] = str(bucket)
                        lines.append(f"{name}_bucket{_format_labels(bucket_labels)} {counts[(label_items, bucket)]}")
                    inf_labels = dict(label_items)
                    inf_labels["le"] = "+Inf"
                    lines.append(f"{name}_bucket{_format_labels(inf_labels)} {totals[label_items]}")
                    lines.append(f"{name}_sum{_format_labels(dict(label_items))} {sums[label_items]}")
                    lines.append(f"{name}_count{_format_labels(dict(label_items))} {totals[label_items]}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()


metrics_registry = MetricsRegistry()
