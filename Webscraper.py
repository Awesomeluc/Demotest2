import urllib.request
from bs4 import BeautifulSoup
import csv

url = "https://www.google.com/search?q=python"

html = urllib.request.urlopen(url).read()
soup = BeautifulSoup(html, "html.parser")

results = []

for result in soup.find_all("div", class_="BNeawe iBp4i AP7Wnd"):
    link = result.find("a").get("href")
    title = result.find("a").get_text()
    description = result.find_next_sibling("div").get_text()

    # Clean data
    link = link.split("/url?q=")[1].split("&sa=")[0]

    # Append data to results
    results.append([title, link, description])

# Write data to CSV file
with open("results.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Title", "Link", "Description"])
    writer.writerows(results)
