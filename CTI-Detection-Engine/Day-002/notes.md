# DAY 002 — Python API + JSON Basics

---

## Project Setup

### Create Project Folder

```bash
mkdir python_api_project
cd python_api_project
````

Creates a new project directory and moves into it.

---

### Create Virtual Environment

```bash
python -m venv venv
```

Creates an isolated Python environment to avoid conflicts with system packages.

---

### Activate Virtual Environment

```bash
source venv/bin/activate
```

When active, terminal shows `(venv)`.

---

### Install Required Library

```bash
pip install requests
```

Requests library is used to make API calls.

---

## Python Script

### Create Python File

```bash
touch api_script.py
```

---

### Final Code

```python
import requests

url = "https://randomuser.me/api/"

response = requests.get(url)

data = response.json()

name = data["results"][0]["name"]["first"]
email = data["results"][0]["email"]
country = data["results"][0]["location"]["country"]

print("Name:", name)
print("Email:", email)
print("Country:", country)
```

---

## Running the Script

```bash
python api_script.py
```

The script:

* Sends API request
* Receives JSON data
* Extracts selected fields
* Prints output

---

## Key Concepts Learned

### API

API allows communication with external servers to fetch data.

Examples:

* Weather API
* User Data API
* Payment API

---

### JSON

JSON is a structured data format used in APIs.

Example:

```json
{
  "name": "John",
  "country": "USA"
}
```

---

## Important Learning Points

* Always use virtual environments
* API data is dynamic
* JSON data is nested
* Understanding JSON structure is critical

---

## Example Output

```
Name: Dale
Email: dale@example.com
Country: Australia
```

(Output changes each run because API returns random users)

---

## What I Learned Today

* Virtual Environment Usage
* Installing Python Libraries
* Making API Calls
* JSON Parsing
* Running Python Scripts

```
