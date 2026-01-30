import os
import tempfile
from app import app


def test_index_loads():
    client = app.test_client()
    rv = client.get('/')
    assert rv.status_code == 200


def test_register_page():
    client = app.test_client()
    rv = client.get('/register')
    assert rv.status_code == 200
