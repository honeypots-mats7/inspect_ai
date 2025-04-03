from pathlib import Path
from inspect_ai._display.core.display import TaskDisplayMetric
from inspect_ai.log._recorders.types import SampleEvent, SampleSummary


class DummySampleBufferDatabase:
    def __init__(
        self,
        location: str,
        *,
        create: bool = True,
        log_images: bool = True,
        log_shared: int | None = None,
        update_interval: int = 2,
        db_dir: Path | None = None,
    ):
        pass

    def start_sample(self, sample: SampleSummary) -> None:
        pass

    def log_events(self, events: list[SampleEvent]) -> None:
        pass

    def complete_sample(self, summary: SampleSummary) -> None:
        pass

    def update_metrics(self, metrics: list[TaskDisplayMetric]) -> None:
        pass

    def remove_samples(self, samples: list[tuple[str | int, int]]) -> None:
        pass

    def cleanup(self) -> None:
        pass
