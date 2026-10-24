from pathlib import Path
import pytest
from pydantic import ValidationError
from app.config import Settings, load_settings

@pytest.mark.parametrize("changes", [
    {"workers": 2}, {"queue_capacity": 0}, {"failure_threshold": -1},
    {"host": "0.0.0.0"}, {"bind_mode": "docker"},
    {"ollama_url": "https://external.example"},
    {"allowed_models": ["other"]}, {"data_root": " "},
    {"num_ctx": 512}, {"inference_timeout_seconds": 1},
    {"unknown_key": 1}, {"failure_window_seconds": "60"},
])
def test_reject_invalid(changes):
    with pytest.raises(ValidationError):
        Settings(**changes)

def test_explicit_docker_mode():
    assert Settings(bind_mode="docker", host="0.0.0.0").workers == 1

def test_relative_root_uses_config_location(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('data_root = "evidence"', encoding="utf-8")
    assert load_settings(path).data_root == str(tmp_path / "evidence")
    assert not (tmp_path / "evidence").exists()

def test_example_matches_defaults():
    path = Path(__file__).resolve().parents[1] / "config.example.toml"
    loaded = load_settings(path).model_dump()
    expected = Settings().model_dump()
    loaded.pop("data_root")
    expected.pop("data_root")
    assert loaded == expected

