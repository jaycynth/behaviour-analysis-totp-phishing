from locust import HttpUser, task, between
import random
class PhishingDetectionTest(HttpUser):
    wait_time = between(1, 5)

    @task
    def simulate_login_attempt(self):
        locations = [
            "New York, USA", "London, UK", "Berlin, Germany", 
            "Tokyo, Japan", "Sydney, Australia", "Cape Town, South Africa", 
            "Nairobi, Kenya", "Lagos, Nigeria", "Cairo, Egypt", "Accra, Ghana"
        ]

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
        ]

        payload = {
            "user_id": f"user_{random.randint(1, 100)}",
            "ip_address": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            "device_id": f"device_{random.randint(1, 50)}",
            "location": random.choice(locations),
            "user_agent": random.choice(user_agents),
            "otp_code_hash": f"hash_{random.randint(1000, 9999)}"
        }

        headers = {
            "Content-Type": "application/json",
        }

        with self.client.post("/api/login-attempt", json=payload, headers=headers, catch_response=True, verify=False) as response:
            if response.status_code != 200:
                response.failure(f"Login attempt failed. Status Code: {response.status_code}, Response: {response.text}")


#locust -f locust-test.py --host http://localhost:8000