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
import re

def clean_text(text):
    # remove HTML tags
    text = re.sub('<[^<]+?>', '', text)
    # remove punctuation and special characters
    text = re.sub('[^A-Za-z0-9]+', ' ', text)
    # convert to lowercase
    text = text.lower()
    # remove extra whitespace
    text = re.sub('\s+', ' ', text).strip()
    return text
import csv

# define the data
data = [
    {'title': 'Article 1', 'author': 'John Doe', 'date': '2022-04-01', 'text': 'This is the text of article 1.'},
    {'title': 'Article 2', 'author': 'Jane Smith', 'date': '2022-04-02', 'text': 'This is the text of article 2.'},
    {'title': 'Article 3', 'author': 'Bob Johnson', 'date': '2022-04-03', 'text': 'This is the text of article 3.'}
]

# define the headers for the CSV file
headers = ['title', 'author', 'date', 'text']

# write the data to a CSV file
with open('data.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    writer.writeheader()
    for article in data:
        writer.writerow(article)
