from ollama_client import Ollamaclient
import os 

client = Ollamaclient(
    url='http://sushi.it.ilstu.edu:8080',
    api_key = os.environ.get('API_KEY'),   #Retrive the API key from the operating system environment
    model="llama3.3:latest"     # Can be changed to a model of your liking
)
#client.reset()   #Uncomment and run code when you want to reset the history, leave commented out when you want to have a continous chat. 
#For long prompts that need to be manual entered, use new lines to keep it neat. (ex. \n) at the end of each sentence. 
response = client.chat("")
print(response)
