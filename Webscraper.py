import requests
from bs4 import BeautifulSoup

# URL of the webpage to scrape
url = "https://www.example.com"

# Send a GET request to the webpage and get its content
response = requests.get(url)
content = response.content

# Parse the HTML content with BeautifulSoup
soup = BeautifulSoup(content, 'html.parser')

# Extract all the links in the webpage
links = soup.find_all('a')
for link in links:
    print(link.get('href'))
