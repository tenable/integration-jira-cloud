import pytest
import tomlkit


@pytest.fixture
def example_config():
    with open('tests/test_config.toml', 'r', encoding='utf-8') as fobj:
        conf = tomlkit.load(fobj)
    return conf
