"""Validated configuration; loading it performs no I/O beyond reading TOML."""
from pathlib import Path
from typing import Literal
import tomllib
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MODELS = ("qwen2.5:3b-instruct-q4_K_M", "llama3.2:3b-instruct-q4_K_M")

class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    data_root: str = "data"
    bind_mode: Literal["local", "docker"] = "local"
    host: Literal["127.0.0.1", "0.0.0.0"] = "127.0.0.1"
    port: int = Field(default=8000, ge=1024, le=65535)
    workers: Literal[1] = 1
    allowed_models: list[str] = Field(default_factory=lambda: list(MODELS))
    ollama_url: Literal["http://127.0.0.1:11434"] = "http://127.0.0.1:11434"
    failure_window_seconds: int = Field(default=60, gt=0)
    success_window_seconds: int = Field(default=300, gt=0)
    activity_window_seconds: int = Field(default=300, gt=0)
    failure_threshold: int = Field(default=5, gt=0)
    inference_timeout_seconds: int = Field(default=300, gt=0)
    response_wait_seconds: int = Field(default=10, gt=0)
    queue_capacity: int = Field(default=20, gt=0)
    upload_max_bytes: int = Field(default=50 * 1024 * 1024, gt=0)
    import_max_events: int = Field(default=100000, gt=0)
    xml_max_depth: int = Field(default=32, ge=2)
    temperature: float = Field(default=0.0, ge=0, le=2)
    num_ctx: int = Field(default=4096, gt=0)
    num_predict: int = Field(default=512, gt=0)
    context_reserve: int = Field(default=256, ge=0)

    @field_validator("data_root")
    @classmethod
    def nonempty_root(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("data_root must not be empty")
        return value

    @field_validator("allowed_models")
    @classmethod
    def fixed_models(cls, value: list[str]) -> list[str]:
        if len(value) != 2 or set(value) != set(MODELS):
            raise ValueError("Both approved local model tags are required")
        return value

    @model_validator(mode="after")
    def coherent(self):
        expected = "127.0.0.1" if self.bind_mode == "local" else "0.0.0.0"
        if self.host != expected:
            raise ValueError("host does not match explicit bind_mode")
        if self.num_predict + self.context_reserve >= self.num_ctx:
            raise ValueError("No context budget remains for input")
        if self.response_wait_seconds > self.inference_timeout_seconds:
            raise ValueError("Response wait exceeds inference timeout")
        return self

def load_settings(path: Path) -> Settings:
    with path.open("rb") as handle:
        settings = Settings.model_validate(tomllib.load(handle))
    root = Path(settings.data_root)
    settings.data_root = str((path.resolve().parent / root).resolve())
    return settings

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    settings = load_settings(args.path)
    print(settings.model_dump_json(indent=2))

