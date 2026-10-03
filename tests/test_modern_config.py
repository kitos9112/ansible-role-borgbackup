"""Borg configuration regressions use synthetic secrets and no live storage."""

import json
import os
from pathlib import Path
import subprocess

from jinja2 import Environment, FileSystemLoader
import yaml
import pytest


ROLE = Path(__file__).parents[1]


def render(**overrides):
    values = yaml.safe_load((ROLE / 'defaults/main.yml').read_text())
    values.update(borg_source_directories=['/tmp/source with spaces'],
                  borg_repository='/tmp/borg-repository',
                  borg_encryption_passphrase='colon: value # hash\nnext line')
    values.update(overrides)
    env = Environment(loader=FileSystemLoader(str(ROLE / 'templates')))
    env.filters['to_json'] = json.dumps
    env.filters['to_nice_yaml'] = lambda value, indent=2: yaml.safe_dump(
        value, indent=indent,
    )
    return env.get_template('config.yaml.j2').render(**values)


def test_special_character_passphrase_roundtrips():
    config = yaml.safe_load(render())
    assert config['encryption_passphrase'] == 'colon: value # hash\nnext line'
    assert config['source_directories'] == ['/tmp/source with spaces']


def test_passcommand_is_not_shadowed_by_empty_passphrase():
    config = yaml.safe_load(render(
        borg_encryption_passphrase='',
        borg_encryption_passcommand='cat /private/passphrase',
    ))
    assert config.get('encryption_passphrase') is None
    assert config['encryption_passcommand'] == 'cat /private/passphrase'


@pytest.mark.skipif(
    os.environ.get('BORG_ROLE_INTEGRATION') != '1',
    reason='Requires explicitly prepared Borg/borgmatic tool caches',
)
def test_current_schema_validates_without_deprecation(tmp_path):
    path = tmp_path / 'synthetic.yaml'
    path.write_text(render())
    result = subprocess.run([
        'uv', 'tool', 'run', '--offline', '--python', '3.12',
        '--from', 'borgmatic==2.1.9',
        'borgmatic', 'config', 'validate', '--config', str(path),
    ], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'deprecated' not in (result.stdout + result.stderr).lower()


def test_multiple_repositories_and_database_hook_are_preserved():
    databases = [{'name': 'synthetic', 'username': 'backup',
                  'password': 'colon: value # hash',
                  'options': '--single-transaction'}]
    config = yaml.safe_load(render(
        borg_repository=['/tmp/a', '/tmp/b'],
        borgmatic_mariadb_databases=databases,
    ))
    assert config['repositories'] == [{'path': '/tmp/a'}, {'path': '/tmp/b'}]
    assert config['mariadb_databases'] == databases
    assert config['local_path'] == '/opt/borgmatic/bin/borg'
    assert config['match_archives'] == 'sh:{hostname}-*'


def test_default_packages_resolve_to_exact_stable_releases():
    defaults = yaml.safe_load((ROLE / 'defaults/main.yml').read_text())
    variables = yaml.safe_load((ROLE / 'vars/main.yml').read_text())
    env = Environment()
    packages = [env.from_string(p).render(**defaults)
                for p in variables['borg_python_packages']]
    assert packages == ['borgbackup==1.4.5', 'borgmatic==2.1.9']


@pytest.mark.skipif(
    os.environ.get('BORG_ROLE_INTEGRATION') != '1',
    reason='Requires explicitly prepared Borg/borgmatic tool caches',
)
def test_real_encrypted_backup_restores_canary(tmp_path):
    borg = subprocess.run([
        'uv', 'tool', 'run', '--offline', '--python', '3.12',
        '--from', 'borgbackup==1.4.5', 'python', '-c',
        'import shutil; print(shutil.which("borg"))',
    ], capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    source = tmp_path / 'source'
    source.mkdir()
    payload = b'Borg recovery acceptance\n' * 100
    (source / 'canary').write_bytes(payload)
    repository = tmp_path / 'repository'
    config = yaml.safe_load(render(
        borg_source_directories=[str(source)], borg_repository=str(repository),
    ))
    config['local_path'] = borg
    config_file = tmp_path / 'config.yaml'
    config_file.write_text(yaml.safe_dump(config))
    config_file.chmod(0o600)
    env = dict(os.environ)
    for key in ['BORG_CACHE_DIR', 'BORG_CONFIG_DIR', 'BORG_SECURITY_DIR']:
        env[key] = str(tmp_path / key.lower())
    base = [
        'uv', 'tool', 'run', '--offline', '--python', '3.12',
        '--from', 'borgmatic==2.1.9',
        'borgmatic', '--config', str(config_file),
    ]
    for action in [
        ['repo-create', '--encryption', 'repokey'],
        ['create', 'check'],
    ]:
        result = subprocess.run(base + action, env=env, capture_output=True,
                                text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
    env['BORG_PASSPHRASE'] = 'colon: value # hash\nnext line'
    listing = subprocess.run([borg, 'list', '--json', str(repository)],
                             env=env, capture_output=True, text=True,
                             timeout=30, check=True)
    archives = json.loads(listing.stdout)['archives']
    assert len(archives) == 1
    restored = tmp_path / 'restored'
    restored.mkdir()
    subprocess.run([borg, 'extract', str(repository) + '::' +
                    archives[0]['name']], cwd=restored, env=env,
                   capture_output=True, text=True, timeout=30, check=True)
    assert (
        (restored / source.relative_to('/') / 'canary').read_bytes() == payload
    )
