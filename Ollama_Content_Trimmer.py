import json
import re

Class Content_Trimmer(self, LLM_input): 
raw_content = LLM_input
raw_content = llm_response['choices'][0]['message']['content']
    def clean_llm_content(raw_text: str) -> str:
    """
    Cleans raw LLM assistant output for human readability.
    Removes markdown symbols, escaped backslashes, and trims whitespace.
    """
    # Remove markdown bold/italic
    text = re.sub(r"(\*\*|\*)", "", raw_text)

    # Replace escaped newlines with real newlines
    text = text.replace("\\n", "\n")

    # Remove backslashes not part of escape sequences
    text = text.replace("\\", "")

    # Collapse multiple newlines into a single newline
    text = re.sub(r"\n{2,}", "\n\n", text)

    # Strip leading/trailing whitespace
    text = text.strip()

    return text

    
