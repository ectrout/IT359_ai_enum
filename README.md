Illinois State University – Cybersecurity Automation Project
This repository contains the work of an Illinois State University cybersecurity research project co-led by Eric Trout and Jake Cirks.
Our goal is to push the boundaries of automated reconnaissance by combining Nmap, Python-based orchestration, and Ollama AI to create a context‑aware, AI‑assisted red‑team analysis pipeline.

🎯 Project Intent
The project aims to automate reconnaissance and early‑stage adversarial analysis by:
• 	Running Nmap to identify open ports, services, versions, and exposed applications
• 	Feeding structured scan data into Ollama AI for contextual interpretation
• 	Mapping potential steps of a cyber kill chain using AI‑assisted reasoning
• 	Leveraging automation + red‑team tooling + AI to accelerate analysis
While exploitation is not the primary objective, achieving a validated exploit path through this system would represent an exceptional success.

📁 Repository Structure
Below are the core Python modules developed for this project:

[ollama_client.py] A modular, extensible client for securely communicating with an Ollama server using its OpenAI‑compatible API.
Features include:
• 	Clean class design for future expansion
• 	Secure API communication
• 	Support for multi‑turn conversations and structured prompts
• 	Designed to integrate seamlessly with the orchestration pipeline

[nmap_scan.py] A purpose‑built class for executing Nmap scans and converting the results into structured JSON.
Key responsibilities:
• 	Running Nmap with predefined or dynamic flags
• 	Parsing XML/CLI output
• 	Formatting results for ingestion by the AI analysis layer
This class is intentionally less modular because it is optimized for a specific workflow: scan → parse → feed into AI.

[Ollama_Content_Trimmer.py] A utility class designed to:
• 	Trim excessive or verbose AI output
• 	Enforce content length limits
• 	Improve downstream parsing and reasoning efficiency
This ensures that the AI’s responses remain structured, concise, and machine‑processable.

🚀 Vision
By combining traditional reconnaissance tools with modern AI reasoning, this project explores how automated systems can:
• 	Identify vulnerabilities faster
• 	Suggest potential attack paths
• 	Provide guided analysis for red‑team operators
• 	Maintain persistent context across multi‑step engagements
