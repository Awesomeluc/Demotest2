import requests
from bs4 import BeautifulSoup
import csv

# specify the URL of the page you want to scrape
url = "https://www.example.com"

# send a GET request to the URL
response = requests.get(url)

# create a BeautifulSoup object to parse the HTML content
soup = BeautifulSoup(response.content, "html.parser")

# extract the data you want to scrape
data = []
for item in soup.find_all("div", {"class": "item"}):
    title = item.find("h2").text.strip()
    price = item.find("div", {"class": "price"}).text.strip()
    data.append((title, price))

# write the data to a CSV file
with open("data.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Title", "Price"])
    writer.writerows(data)
