import requests

# This function will fetch data from the API
def get_data():
    url = "https://randomuser.me/api/?results=5"
    responce = requests.get(url)
    data = responce.json()
    return data

# This function will return the countries
def get_countries(data):
    countries = []

    for user in data["results"]:
        country = user["location"]["country"]
        countries.append(country)

    return countries

# this function will count
def count_countries(country_list):
    freq = {}

    for c in country_list:
        if c in freq:
            freq[c] += 1
        else:
            freq[c] = 1

    return freq

# This is the main programm
def main():
    data = get_data()
    countries = get_countries(data)
    print(countries) #DEBUG LINE
    result = count_countries(countries)

    print("Country Count: ")
    for k, v in result.items():
        print(k, v)

main()
