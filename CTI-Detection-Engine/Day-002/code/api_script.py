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
