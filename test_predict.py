import requests

BASE_URL = "http://127.0.0.1:8000/predict"

def test_url(url: str):
    payload = {"url": url}
    r = requests.post(BASE_URL, json=payload)
    print(f"\nURL: {url}")
    print("Response:", r.json())

def main():
    # Benign example
    test_url("https://vle.unikl.edu.my/")

    # Phishing example
    test_url("http://paypal-login.tk/")

    # Defacement example
    test_url("http://www.szabadmunkaero.hu/cimoldal.html?start=12")

    # Malware example
    test_url("http://malware-download.com/file.exe")

if __name__ == "__main__":
    main()