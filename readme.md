# LinkLens

## Overview

LinkLens is an AI-powered cybersecurity assistant and URL threat analysis platform designed to help users identify potentially malicious websites and learn about cybersecurity threats.

Users can scan suspicious URLs before visiting them to receive a detailed threat assessment, including verdicts, threat indicators, confidence levels, and supporting evidence from integrated threat intelligence sources. In addition to URL analysis, LinkLens provides an AI cybersecurity assistant that can answer questions related to malware, phishing attacks, attack techniques, threat actors, cybersecurity best practices, and defensive security concepts.

The goal of this project is to improve cybersecurity awareness and help users make safer decisions online by combining threat intelligence, AI-assisted explanations, and conversational cybersecurity education in a single platform.

## Features

### AI Cybersecurity Assistant

* Chat with an AI assistant specialized in cybersecurity topics.
* Ask questions about malware, phishing, ransomware, attack techniques, threat actors, security best practices, and defensive strategies.
* Continue previous conversations through persistent chat sessions.
* Context-aware conversations with memory of recent interactions.

### URL Threat Analysis

* Scan suspicious URLs before visiting them.
* Receive detailed threat assessments and risk verdicts.
* View threat indicators, supporting evidence, and detected threat categories.
* Analyze potential phishing, malware distribution, and other malicious activity.
* Ask follow-up questions about scan results using natural language.

### User Accounts & Session Management

* Secure user registration and authentication.
* Persistent chat history and URL analysis history.
* Ability to revisit previous investigations and continue conversations.
* Session management with saved analysis records.

### Investigation Workflow

* Dedicated URL investigation sessions.
* Follow-up questioning based on previous URL analysis results.
* Structured threat explanations and recommendations.
* Organized history of cybersecurity investigations.


## Tech Stack

### Backend

* Python
* Django
* SQLite Database

### AI & Machine Learning

* Qwen (Large Language Model)
* Hugging Face Transformers
* PyTorch
* Sentence Transformers
* FAISS Vector Database
* Retrieval-Augmented Generation (RAG)


### Threat Intelligence APIs

* VirusTotal API
* URLHaus

### Frontend

* HTML
* CSS
* JavaScript

### Data Processing & Utilities

* NumPy
* Pandas
* JSON



## Architecture

### AI Assistant Workflow

#### 1. User Query Processing

The user submits a cybersecurity-related question, such as malware analysis, attack techniques, threat actors, mitigation strategies, or general cybersecurity concepts.

#### 2. Intent Detection

The query is analyzed to determine which cybersecurity entities are being referenced, such as malware, attack patterns, intrusion sets, threat actors, tools, or vulnerabilities. This helps narrow down the information required to answer the question accurately.

#### 3. Query Type Classification

The system determines the type of information requested by the user:

* **Overview** – The user wants an explanation of a specific cybersecurity concept or entity.
* **Relationship** – The user wants information about how multiple entities are connected (e.g., malware used by a threat actor, attack patterns associated with a malware family, mitigation techniques, etc.).
* **General** – The query is broad or conversational and does not directly reference specific cybersecurity entities.

This classification helps retrieve only the most relevant information rather than overwhelming the model with unnecessary context.

#### 4. Context Retrieval

The system retrieves cybersecurity knowledge using multiple retrieval strategies:

**Exact Entity Matching**

* Detects known cybersecurity entities directly from the query.
* Retrieves information associated with those entities.

**N-Gram Fuzzy Matching**

* Generates query n-grams and searches for partial matches against known cybersecurity entities.
* Helps identify entities even when the user does not use exact terminology.

#### 5. Semantic Retrieval with FAISS

If entity-based retrieval does not produce sufficient results, the query is embedded and searched against a FAISS vector database.

The vector database stores embeddings of cybersecurity knowledge and retrieves semantically similar information, allowing the assistant to answer broader cybersecurity questions.

#### 6. Conversation Memory

To maintain context across long conversations:

* Previous messages are retrieved from the current chat session.
* Older conversations are summarized when necessary.
* Recent messages are preserved in full detail.
* A token-aware memory system ensures the prompt remains within the model's context window.

#### 7. Prompt Construction

The final prompt combines:

* System instructions
* Retrieved cybersecurity knowledge
* Conversation memory
* User query

This provides the model with both relevant knowledge and conversational context.

#### 8. Response Generation

The constructed prompt is sent to the Qwen Large Language Model.

The model is configured for analytical and factual cybersecurity responses, prioritizing accuracy and relevance over creative generation.

#### 9. Final Response

The generated response is returned to the user and stored within the chat session for future reference.


### URL Analysis Workflow

#### 1. URL Submission

The user submits a URL they believe may be suspicious, malicious, or unsafe.

#### 2. Threat Intelligence Collection

The submitted URL is analyzed using multiple threat intelligence sources:

* VirusTotal
* URLHaus

These services provide information about detections, reputation, malicious activity, and known threat classifications associated with the URL.

#### 3. Threat Analysis Engine

The raw results from the threat intelligence sources are processed by a custom analysis engine that aggregates and evaluates the findings.

The analysis engine generates:

* Verdict
* Confidence Level
* Dominant Threat Type
* Supporting Evidence
* Evidence Summary
* Threat Distribution
* Supporting Detection Engines
* Key Findings

This step converts raw API responses into a structured threat assessment.

#### 4. AI-Powered Explanation

The structured analysis is provided to the Qwen Large Language Model.

The model generates a human-readable security report that explains:

* The overall verdict
* Confidence in the assessment
* Threat categories detected
* Supporting evidence
* Detection sources
* Potential risks associated with the URL
* Recommended actions for the user

This allows users to understand the findings without needing cybersecurity expertise.

#### 5. Follow-Up Investigation

Each URL analysis is stored as a dedicated investigation session.

Users can ask follow-up questions such as:

* What does this threat mean?
* How can this affect my system?
* What precautions should I take?
* Why was this URL flagged?

The assistant combines the stored analysis results with additional cybersecurity knowledge to provide contextual explanations and recommendations.



## Installation & Setup

### Prerequisites

Before running LinkLens locally, ensure the following are installed:

* Python 3.10+
* Git
* Virtual Environment (recommended)

### Clone the Repository

```bash
git clone <repository-url>
cd LinkLens
```

### Create a Virtual Environment

```bash
python -m venv venv
```

Activate the environment:

**Windows**

```bash
venv\Scripts\activate
```

**Linux / macOS**

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create a `.env` file in the project root directory and add the required API keys:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLHAUS_API_KEY=your_urlhaus_api_key
```

### Apply Database Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### Create a Superuser (Optional)

```bash
python manage.py createsuperuser
```

### Run the Development Server

```bash
python manage.py runserver
```

Open your browser and navigate to:

```text
http://127.0.0.1:8000/
```

---

## System Requirements

### Minimum Requirements

* 8 GB RAM
* Multi-core CPU
* 5 GB available storage

### Recommended Requirements

* 16 GB RAM
* Modern multi-core CPU
* SSD storage

### AI Model Requirements

LinkLens uses a locally hosted Qwen Large Language Model for cybersecurity assistance and explanation generation. Performance will depend on available system resources and the selected model size.

```
```


## Future Improvements

Planned improvements for future versions of LinkLens include:

* Additional threat intelligence integrations
* File and attachment analysis
* Improved URL analysis reliability and confidence scoring
* Expanded cybersecurity knowledge base
* Advanced threat correlation and investigation workflows
* Enhanced user interface and visualization features
* Deployment and production scaling improvements
* Support for additional LLMs and model configurations


## Screenshots 

### Home Dashboard
![Home Dashboard](Screenshots/Home.png)

### AI Cybersecurity Assistant
![AI Assistant](Screenshots/Chat_Session1.png)

![AI Assistant](Screenshots/Chat_Session2.png)


### Trojan URL Analysis

![Trojan Analysis](Screenshots/URL_Analysis_unsafe1.png)

![Trojan Analysis](Screenshots/URL_Analysis_unsafe2.png)

### URL Investigation Follow-up

![Follow-up Investigation](Screenshots/URL_Analysis_Unsafe_with_followup_question.png)

![Follow-up Investigation](Screenshots/URL_Analysis_unsafe_followup_response.png)

### Safe URL Analysis

![Safe URL Analysis](Screenshots/URL_Analysis_safe_url1.png)

![Safe URL Analysis](Screenshots/URL_Analysis_safe_url2.png)

```
Project Structure

│   manage.py
│   readme.md
│
├───assistant
│   │   admin.py
│   │   ai_response.py
│   │   apps.py
│   │   assistant.py
│   │   data_loader.py
│   │   embeddings.py
│   │   llm.py
│   │   models.py
│   │   retreival.py
│   │   scan_url.py
│   │   tests.py
│   │   urls.py
│   │   views.py
│   │   __init__.py
│   │
│   ├───Enterprise  # Enterprise ATT&CK STIX data
│   │
│   ├───ICS/  # ICS ATT&CK STIX data
│   │         
│   ├───Mobile/ # Mobile ATT&CK STIX data 
│   │
│   │    
│   │
│   ├───templates
│       └───assistant
│               chat.html
│               home.html
│               login.html
│               register.html
│               scan_url.html
│   
│
├───indices
│       doc_mitre-all
│
├───LinkLens_V2
│       asgi.py
│       settings.py
│       urls.py
│       wsgi.py
│       __init__.py
│   
│
└───Screenshots
        Chat_Session1.png
        Chat_Session2.png
        Home.png
        URL_Analysis_safe_url1.png
        URL_Analysis_safe_url2.png
        URL_Analysis_unsafe1.png
        URL_Analysis_unsafe2.png
        URL_Analysis_unsafe_followup_response.png
        URL_Analysis_Unsafe_with_followup_question.png

```

## Knowledge Base

LinkLens uses MITRE ATT&CK STIX datasets across multiple domains:

- Enterprise ATT&CK
- Mobile ATT&CK
- ICS ATT&CK

The datasets contain information about:

- Attack Patterns
- Malware
- Intrusion Sets
- Threat Actors
- Tools
- Campaigns
- Mitigations
- Relationships

These datasets are processed and indexed to support retrieval-augmented generation (RAG) and contextual cybersecurity explanations.



## Disclaimer

This project is intended for educational and research purposes.

URL analysis results are based on available threat intelligence sources and AI-generated explanations. Users should not rely solely on the results of this tool when making security decisions and should perform additional verification where appropriate.


## Why I Built This

I built LinkLens to explore Retrieval-Augmented Generation (RAG), conversation memory systems, threat intelligence integration, and practical cybersecurity applications of Large Language Models. The project evolved from a simple URL scanning application into a cybersecurity assistant capable of conducting investigations and maintaining conversational context.














