import requests, csv

BASE_URL = "http://localhost:3000"

# **Required behavior**
# 1. Test `/rest/products/search` with a harmless text marker and one non-executable HTML input; check for unchanged reflection in the HTTP response.
# 2. Compare a normal search term with at least two **simple SQL syntax probes** (for example `'` and `')`). Check for HTTP 500 responses or recognizable database error text.
# 3. Inspect `Content-Security-Policy` and `X-Content-Type-Options` on the homepage. Record missing headers as **configuration review**, not proof of exploitation.
# 4. If a `Server` header exists, report it as **informational**, not automatically high severity.
# 5. Prevent duplicate alerts.
# 6. Print a concise summary with the **category, endpoint, observation and review status**.
# 7. Save findings to `vulnerability_findings.csv`.
# 8. Handle failed requests gracefully. If no indicators are found, explain that this **does not prove the site is secure**.



def search_probe(url, query):
    probe_response = requests.get(BASE_URL + url, params={"q": query}, timeout=5)
    check_headers(probe_response)
    if q in probe_response.text:
        print("Marker appears in the response — investigate its context")
    else:
        print("Marker was not found in this response")
    
def response_probe(url, probe):
    probe_response = requests.get(BASE_URL + url, params={"q": probe}, timeout=5)
    check_headers(probe_response)
    print("Probe input status:", probe_response.status_code)

def check_headers(request):
    record = {
            "endpoint": request.url,
            "status": request.status_code,
            "length": len(request.content),
            "content-type": request.headers.get("Content-Type", "")
        }
    with open("records.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["endpoint", "status", "length", "content-type"])
        writer.writeheader()
        writer.writerows([record])
    print("Status code:", record["status"])
    print("Response length:", record["length"])
    print("Content type:", record["content-type"])

    if "Server" in request.headers:
        # header found
        print("Server header found")
    return request


# queries
search_urls = ["/rest/products/search", "/"]
queries = ["apples", "bananas"]
for q in queries:
    for u in search_urls:
        search_probe(u, q)

response_probe("/rest/products/search", "'")

print("Saved practice_records.csv")
