from assistant.llm import get_llm, get_device, get_tokenizer, get_summarizer
from .models import ChatSession, Message, ChatSummary
from .retreival import retrieve_previous_messages
model = get_llm()
device = get_device()
tokenizer = get_tokenizer()


summarizer_tokenizer, summarizer_model = get_summarizer()


def count_tokens(prompt):
    return len(tokenizer(prompt)["input_ids"])


def summarize_chat_history(session):
   messages = retrieve_previous_messages(session)

   if not messages:
       return None
   summary_prompt = f"""
    summarize the following conversation between a user and an assistant in a concise manner, 
    focusing on key points and important information. 
    The summary should be in English and should capture the essence of the conversation without losing critical details.

    Conversartion:
    {messages}
    """
   
   input_ids = summarizer_tokenizer(
       summary_prompt,
       return_tensors="pt",
       max_length=4096,
       truncation=True
   ).to(device)

   summar_ids = summarizer_model.generate(
       **input_ids,
       max_new_tokens=200,
       do_sample=False,
   )

   summary = summarizer_tokenizer.decode(
        summar_ids[0],
        skip_special_tokens=True
    )
   return summary


def to_get_memory_token_limit(context, query):
    prompt = """
        You are a Cybersecurity Assistant
        Rules:
        - Answer ONLY using the provided context, chat history.
        - Do not use external knowledge.
        - If the context does not contain enough information,
        explicitly say so.
        - Do not infer or guess facts.
        - Do not mention information not present in the context.    
        
        Context:

        Conversation Summary:

        Recent Messages:

        User's Query:

        Answer:
        """

    system_prompt_token = count_tokens(prompt)

    context_tokens = count_tokens(context)
    query_tokens = count_tokens(query)

    output_reserve = 1000

    memory_token_limit = 6096 - (system_prompt_token + context_tokens + query_tokens + output_reserve)

    return memory_token_limit



def truncate_to_tokens(text, max_tokens):
    tokens = summarizer_tokenizer(
        text,
        return_tensors="pt",
        max_length = max_tokens,
        truncation=True
    )

    return tokenizer.decode(tokens["input_ids"][0], skip_special_tokens=True)


def get_chat_memory(session, memory_token_limit):
    messages = retrieve_previous_messages(session)

    all_messages = "\n\n".join([f"{msg['role']}: {msg['content']}" for msg in messages])

    all_messages_tokens = count_tokens(all_messages)

    if all_messages_tokens <= memory_token_limit:
        return{
            "memory_text": all_messages,
            "summary": None,
            "previous_messages": all_messages
        }
    else:
        summary = ChatSummary.objects.filter(session=session).first()

        if summary:
            unsummarized_messages = Message.objects.filter(session=session, id__gt=summary.last_message_id).order_by("created_at")
        else:
            unsummarized_messages = Message.objects.filter(session=session).order_by("created_at")

        last_20_messages = "\n\n".join([f"{msg.role}: {msg.content}" for msg in unsummarized_messages[-20:]])

      
        messages_to_summarize = "\n\n".join([f"{msg.role}: {msg.content}" for msg in unsummarized_messages[:-20]])
        summary_text = summary.summary if summary else ""
        if len(unsummarized_messages) > 20:
            combined_text = f"""
            Existing Summary:
            {summary_text}

            New Messages to Summarize:
            {messages_to_summarize}
            """
            summary_text = summarize_chat_history(combined_text)

            messages_that_were_summarized = list(unsummarized_messages[:-20])

            if not summary:
                summary = ChatSummary.objects.create(
                    session=session,
                    summary=""
                )

            summary.summary = summary_text
            summary.last_message_id = (messages_that_were_summarized[-1].id)

            summary.save()
    memory_text = f"""
    Conversation Summary:
    {summary_text}

    Recent Messages:
    {last_20_messages}
    """

    return {
        "memory_text": memory_text,
        "summary": summary_text,
        "previous_messages": last_20_messages
    }



def build_prompt_context(session, context, query, memory_token_limit):
    chat_memory = get_chat_memory(session, memory_token_limit)

    memory_text = chat_memory["memory_text"]

    summary = chat_memory["summary"]
    previous_messages = chat_memory["previous_messages"]

    prompt_context = f"""
    You are a Cybersecurity Assistant
    Rules:
    1. Use information from the provided Context and Chat History whenever possible.

    2. If the Context and Chat History contain sufficient information,
    base your answer primarily on them.

    3. If the Context and Chat History are incomplete, you may use your
    cybersecurity knowledge to provide additional explanation.

    4. Clearly distinguish between:
    - Information supported by the provided Context/Chat History.
    - General cybersecurity knowledge.

    5. Never invent specific facts about malware, threat actors,
    vulnerabilities, incidents, organizations, or entities that are
    not supported by the provided Context.

    6. If neither the Context, Chat History, nor your cybersecurity
    knowledge are sufficient, explicitly state that you do not have
    enough information.

    7. Prioritize accuracy over completeness.  
    
    Context:
    {context}

    Conversation Summary:
    {memory_text}

    User's Query:
    {query}

    Answer:
    """
    return prompt_context
   


def build_url_analysis_context(analysis):
    return f"""
    URL Analysis Data:

    Verdict: {analysis.get("verdict")}
    Confidence: {analysis.get("confidence")}
    Key Findings: {analysis.get("key_findings")}

    Dominant threats AntiVirus: {analysis.get("dominant_threat_av")} 
    Dominant_threat Reputation: {analysis.get("dominant_threat_reputation")}

    Evidence Summary: {analysis.get("evidence_summary")}

    Supporting Engines: {analysis.get("supporting_engines")}

    Threat Distribution: {analysis.get("threat_distribution")}

    Conflicting Assessment: {analysis.get("conflicting_assesment")}

    URLhaus Detected: {analysis.get("urlhaus_detected", False)}
    """

def build_url_prompt(analysis_context):
    prompt = f"""
    <instructions>
    You are an expert cybersecurity analyst. Write a highly professional, cohesive security report based on the URL data. 
    You are strictly forbidden from using Markdown, bolding (**), bullet points (-), colons for labels (Verdict:), or conversational filler.
    Write exactly four paragraphs. Follow the EXACT structure of the Output Template below.
    </instructions>
    
    URL Scan Data:
    {analysis_context}

    <output_template>
    The analyzed URL has resulted in a verdict of [insert verdict], and we assess this with a [insert confidence] level of confidence. [Add one sentence explaining what this verdict means for the user].

    Our analysis identified several key findings regarding the URL's behavior. [Write 2-3 sentences summarizing the AntiVirus and Reputation threats smoothly].

    A review of the underlying evidence shows [Write 2-3 sentences explaining the supporting engines and explicitly mention if there are conflicting assessments].

    Given these findings, you should [Write 2-3 sentences of clear, actionable next steps based on the verdict].
    </output_template>
    """

    return prompt


def build_url_followup_prompt(analysis_context, user_query, retrieved_context):
    prompt = f"""
    You are a Cybersecurity URL Analysis Assistant.

    The user is asking a follow-up question about a previously analyzed URL.

    URL Analysis Results:
    {analysis_context}

    Additional Cybersecurity Context:
    {retrieved_context}

    User Question:
    {user_query}

    Instructions:
    1. Use the URL Analysis Results as the primary source of information.
    2. Use the Additional Cybersecurity Context to explain concepts and findings.
    3. Do not invent scan results that are not present in the URL Analysis Results.
    4. If the analysis does not contain enough information to answer the question, clearly state that limitation.
    5. Explain which findings are most relevant to the user's question.

    FORMATTING RESTRICTIONS (STRICT):
    - DO NOT use the hash character ('#') anywhere in your response for headers or titles.
    - DO NOT use any asterisks (**) or star marks for bolding or emphasis.
    - To separate sections or create headers, use ALL CAPS on a new line (e.g., KEY FINDINGS:).
    - Use clean, standard bullet points (-) or numbered lists (1.) for itemized information.

    Answer:
    """

    return prompt
        

def get_response(prompt_context):

  input_ids = tokenizer(
      prompt_context,
      return_tensors = "pt",
      max_length = 6096,
      truncation = True
  ).to(device)


  response_ids = model.generate(
      **input_ids,
      max_new_tokens = 800,
      do_sample = True,
      temperature = 0.3,
      top_p = 0.8,
  )


  response_generated = tokenizer.decode(
      response_ids[0],
      skip_special_tokens = True
  )

  print("=" * 80)
  print("RAW RESPONSE", response_generated)
  print("=" * 80)


  response = response_generated[len(prompt_context):].strip()

  print(tokenizer(prompt_context)["input_ids"].__len__())

  return  response