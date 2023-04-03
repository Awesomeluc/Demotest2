import os
import requests
import json
import pytube

# Your Twitch API credentials
client_id = 'your_client_id'
access_token = 'your_access_token'
channel_name = 'your_channel_name'

# Directory to save the downloaded video
download_dir = 'download_directory'

# Get the video ID and creation date of the latest stream
url = f'https://api.twitch.tv/helix/videos?user_login={channel_name}&first=1&sort=time'
headers = {'Client-ID': client_id, 'Authorization': f'Bearer {access_token}'}
response = requests.get(url, headers=headers).json()
latest_video = response['data'][0]
video_id = latest_video['id']
created_at = latest_video['created_at']

# Check if the video is the latest one on the channel
if created_at != latest_video['published_at']:
    print("The latest video is not available for download yet. Please try again later.")
else:
    # Download the video
    youtube_url = f'https://www.twitch.tv/videos/{video_id}'
    youtube = pytube.YouTube(youtube_url)
    video = youtube.streams.filter(adaptive=True, file_extension='mp4').order_by('resolution').desc().first()
    filename = video.default_filename
    download_path = os.path.join(download_dir, filename)
    video.download(output_path=download_dir)
    print(f"The video '{filename}' has been downloaded to '{download_path}'")
