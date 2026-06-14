import os
from dotenv import load_dotenv
from google import genai

# Explicitly load the environment variables from your .env file
load_dotenv()

# The client will now successfully pull the token from os.environ["GEMINI_API_KEY"]
client = genai.Client()

print("Environment loaded and API client initialized successfully!")

# Test listing models to verify your new AQ. key works
try:
    for model in client.models.list():
        print(f" - {model.name}")
except Exception as e:
    print(f"Authentication failed: {e}")
