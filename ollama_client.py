import os
import json
import requests

#This is designed to be a class framework of API calls engaging with Ollama 


class Ollamaclient:
    ##############################################################
    #           Start the frame for the class                    #
    ##############################################################

    #Build the constructor
    def __init__(self, url: str, api_key: str, model: str,timeout: int = 180, history_file="history.json" ):
        self.url = url
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.history_file = history_file

        #Load converation history if it exists
        self.history = self._load_history() 


    #Handle the authentication through the headers
    def _headers(self) -> dict:
        headers = {
        'Authorization': f'Bearer {self.api_key}',
        'Content-Type': 'application/json'
        }
        return headers
    #Load any history if the file exists
    def _load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, "r") as f:
                return json.load(f)
        return []   #Return history 
    #Save any history to the file
    def _save_history(self):
        with open(self.history_file, "w") as f:
            json.dump(self.history, f, indent=2)
    
    ##############################################################
    #       Start of core chat methodoly                         #
    ##############################################################

    def chat(self, message: str, temperature: float = 0.2) -> str:
        endpoint_url = f"{self.url}/api/chat/completions"

        #Add the message to history 
        self.history.append({"role": "user", "content": message})

        data = {
            "model" : self.model,
            "messages": self.history, 
            "temperature" : temperature
        }

        try:
            response = requests.post(
                endpoint_url,
                headers = self._headers(), 
                json = data, 
                timeout = self.timeout
            )
            response.raise_for_status()
            payload = response.json()

            reply = payload["choices"][0]["message"]["content"]

            #Use the assistant for reply
            self.history.append({"role": "assistant", "content": reply})

            #Save the new updated history
            self._save_history()

            return reply 
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API request failed: {e}")
        
    #Resets the chat history 
    def reset(self):
        self.history =[]   #Create new empty history
        self._save_history()    # Save the new empty history
        

