# The AI

# Download all the necessary libraries
import google.generativeai as ai
from dotenv import load_dotenv
import os

load_dotenv()

class Gemini_AI:
    def __init__(self, model_name):
        self.model_name = model_name
        self.api_key = os.getenv("GEMINI_API_KEY")

        ai.configure(api_key=self.api_key)

        self.model = ai.GenerativeModel(self.model_name)


    def generate_response(self, input_text):
            response = self.model.generate_content(input_text)
            return response

