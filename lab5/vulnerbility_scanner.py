# **Required behavior**
# 1. Test `/rest/products/search` with a harmless text marker and one non-executable HTML input; check for unchanged reflection in the HTTP response.
# 2. Compare a normal search term with at least two **simple SQL syntax probes** (for example `'` and `')`). Check for HTTP 500 responses or recognizable database error text.
# 3. Inspect `Content-Security-Policy` and `X-Content-Type-Options` on the homepage. Record missing headers as **configuration review**, not proof of exploitation.
# 4. If a `Server` header exists, report it as **informational**, not automatically high severity.
# 5. Prevent duplicate alerts.
# 6. Print a concise summary with the **category, endpoint, observation and review status**.
# 7. Save findings to `vulnerability_findings.csv`.
# 8. Handle failed requests gracefully. If no indicators are found, explain that this **does not prove the site is secure**.

import requests, csv

BASE_URL = "http://localhost:3000"

def xss_check(url, test):
    print("Testing for XSS...")
    try:   
        probe_response = requests.get(BASE_URL + url, params={"q": test}, timeout=5)
        if test in probe_response.text:
            print("Possible XSS found")
            record(probe_response, catagory="high", observation="<p> injected into page", review="Yes")
        else:
            print("No XSS found. This does not prove the site is insecure.")
            record(probe_response, catagory="none", observation="<p> injected into page", review="No")
    except requests.RequestException as e:
        print("Request failed:", e)
    
def sqli_test(url, test):
    print("Testing for SQL Injection...")
    try:
        probe_response = requests.get(BASE_URL + url, params={"q": test}, timeout=5)
        if probe_response == 500:
            print("Possible SQLi found")
            record(probe_response, catagory="high", observation=f"Used {test} to test", review="Yes")
        else:
            print("No SQLi found. This does not prove the site is insecure.")
            record(probe_response, catagory="none", observation=f"Used {test} to test", review="No")
    except requests.RequestException as e:
        print("Request failed:", e)


def header_test(headers):
    print("Testing Headers...")
    try:
        probe_response = requests.get(BASE_URL, timeout=5)
        for h in headers:
            if "Server" in probe_response.headers:
                print("Server header found")
                record(probe_response, catagory="info", observation="Server header found", review="Yes")
            elif h in probe_response.headers:
                print(h, "found")
                record(probe_response, catagory="medium", observation=f"{h} header found", review="Yes")
            else:
                print(h, "not found. This does not prove the site is insecure.")
                record(probe_response, catagory="none", observation=f"{h} header not found", review="No")
        print("To scan for additional headers, configure them in the function parameters")
    except requests.RequestException as e:
        print("Request failed:", e)


def record(request, catagory, observation, review):
    endpoint = request.url
    record_data = {
        "endpoint": endpoint,
        "catagory": catagory,
        "observation": observation,
        "review": review,
    }

    with open("vulnerability_findings.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["endpoint", "catagory", "observation", "review"]
        )

        if file.tell() == 0:
            writer.writeheader()

        writer.writerow(record_data)

    print(f"Endpoint: {endpoint}\nCatagory: {catagory}\nObservation: {observation}\nReview: {review}")
    return request


# 1. test for XSS reflection
xss_check("/rest/products/search", "<p>Test for XSS</p>")

# 2. test for SQLi
sqli_test("/rest/products/search", "'")
sqli_test("/rest/products/search", "')")

# 3. header test
header_test(["Content-Security-Policy", "X-Content-Type-Options"])

