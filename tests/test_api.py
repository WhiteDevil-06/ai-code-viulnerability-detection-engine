import io
import pytest
from main import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_api_status(client):
    response = client.get('/api/status')
    assert response.status_code == 200
    data = response.get_json()
    assert 'engine_ready' in data

def test_api_scan_code(client):
    code_text = "def safe_code():\n    pass"
    response = client.post('/api/scan/code', json={'code': code_text})
    # If engine is offline (e.g. models not trained yet in test env), status will be 503, which is valid.
    # Otherwise it will be 200. We check either outcome is handled cleanly.
    assert response.status_code in [200, 503]
    if response.status_code == 200:
        data = response.get_json()
        assert 'files_scanned' in data
        assert 'vulnerabilities' in data

def test_api_scan_file(client):
    file_content = b"def search_user(user_id):\n    query = f'SELECT * FROM users WHERE id = {user_id}'\n    cursor.execute(query)"
    data = {
        'file': (io.BytesIO(file_content), 'test_scan.py')
    }
    response = client.post('/api/scan/file', data=data, content_type='multipart/form-data')
    assert response.status_code in [200, 503]
    if response.status_code == 200:
        res_json = response.get_json()
        assert res_json['target'] == 'test_scan.py'
        assert res_json['files_scanned'] == 1
        assert 'vulnerabilities' in res_json

def test_api_scan_file_invalid_type(client):
    file_content = b"def invalid_type(): pass"
    data = {
        'file': (io.BytesIO(file_content), 'test_scan.txt')
    }
    response = client.post('/api/scan/file', data=data, content_type='multipart/form-data')
    assert response.status_code == 400
    res_json = response.get_json()
    assert 'error' in res_json
