import requests
import os

def chat_with_model(token):
    prompt = input("Enter a prompt: ")
    """
    Sends a message to the language model API and returns the response.
    
    Args:
        token (str): The API key or authentication token.
    
    Returns:
        dict: The API response as a JSON object.
    """
    url = 'http://sushi.it.ilstu.edu:8080/api/chat/completions'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    data = {
      "model": "llama3.3:latest",
      "messages": [
        {
          "role": "user",
          "content": f"{prompt}"
        }
      ]
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()  # Raise an exception for HTTP errors
        if 'application/json' in response.headers['Content-Type']:
            return response.json()
        else:
            raise ValueError("Invalid response content type")
    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
    except Exception as e:
        print(f"Error: {e}")

# Store the API key securely using environment variables
api_key = os.environ.get('API_KEY')
if api_key is None:
    print("Please set the API_KEY environment variable")
else:

    print(chat_with_model(api_key))

def ask_ai(token, prompt):
    url = 'http://sushi.it.ilstu.edu:8080/api/chat/completions'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    data = {
      "model": "llama3.3:latest",
      "messages": [
        {
          "role": "user",
          "content": prompt
        }
      ]
    }
    response = requests.post(url,headers=headers,json=data)
    return response.json()


