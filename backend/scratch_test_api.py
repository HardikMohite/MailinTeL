import time
import requests

def test_api_speed():
    print("Testing GET http://127.0.0.1:8000/api/v1/emails?skip=0&limit=100...")
    for i in range(3):
        t0 = time.perf_counter()
        resp = requests.get("http://127.0.0.1:8000/api/v1/emails?skip=0&limit=100")
        elapsed = (time.perf_counter() - t0) * 1000
        print(f"  Call {i+1}: {elapsed:.2f} ms | Status: {resp.status_code} | Items count: {len(resp.json().get('items', []))}")

if __name__ == "__main__":
    test_api_speed()
