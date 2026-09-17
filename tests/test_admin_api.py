import runpy
import os
import json
import sqlite3
import pytest

# Ensure we import the app after seeding so DB has data
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED_PATH = os.path.join(BASE_DIR, 'scripts', 'seed_sample_data.py')

# Run the seed script to populate the DB for tests
runpy.run_path(SEED_PATH, run_name='__main__')

from app import app
import auth

# Replace the require_role decorator with a no-op for tests
orig_require_role = auth.require_role

def noop_require_role(_roles):
    def decorator(f):
        return f
    return decorator

auth.require_role = noop_require_role

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


def test_get_admin_users(client):
    resp = client.get('/api/admin/users')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert isinstance(data.get('users'), list)


def test_set_role_disable_delete_flow(client):
    # Use the seeded clerk user id
    clerk_id = 'clerk_test_user_1'

    # Set role
    resp = client.post(f'/api/admin/user/{clerk_id}/role', json={'role': 'admin'})
    assert resp.status_code == 200
    d = resp.get_json()
    assert d['success'] is True and d['role'] == 'admin'

    # Disable user
    resp = client.post(f'/api/admin/user/{clerk_id}/disable', json={'disabled': True})
    assert resp.status_code == 200
    d = resp.get_json()
    assert d['success'] is True and d['disabled'] is True

    # Delete user
    resp = client.delete(f'/api/admin/user/{clerk_id}')
    assert resp.status_code == 200
    d = resp.get_json()
    assert d['success'] is True

    # Confirm deletion
    db_path = os.path.join(BASE_DIR, 'cyberguard.db')
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM clerk_users WHERE clerk_user_id = ?', (clerk_id,))
    assert cur.fetchone()[0] == 0
    conn.close()

# Restore original decorator to avoid side-effects if tests re-run
auth.require_role = orig_require_role
