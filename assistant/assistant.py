from assistant.data_loader import entity_chunk
from assistant.scan_url import search_virus_total, url_haus
from assistant.retreival import understand_query_intent, relationship_queries, generate_n_grams, resolve_entity, get_context, final_context, processing_attributes
from assistant.ai_response import build_prompt_context, get_response, to_get_memory_token_limit, get_chat_memory, build_url_analysis_context, build_url_prompt, build_url_followup_prompt
from assistant.models import ChatSession, Message, ChatSummary


def ask_assistant(query, session):
    intent = understand_query_intent(query)

    ngrams = generate_n_grams(query)

    best_query_type = relationship_queries(query, intent=intent) #Overvoew, Relationship, General

    context_fuzzy = resolve_entity(query=query, intent=intent, best_query_type=best_query_type, entity_chunk=entity_chunk, ngrams=ngrams)

    if context_fuzzy:
        print("Context found through fuzzy matching. Using it to generate response.")

        memory_token_limit = to_get_memory_token_limit(context=context_fuzzy, query=query)

        prompt_context = build_prompt_context(session=session, context=context_fuzzy, query=query, memory_token_limit=memory_token_limit)
        response = get_response(prompt_context=prompt_context)
        
        print("Assistant: ", response)
        
        return response
    else:
        print("No relevant context found through fuzzy matching. Proceeding with FAISS-based approach.")
        retrieved_chunks = get_context(query=query, entity_chunk=entity_chunk)

        context = final_context(retrieved_chunks=retrieved_chunks, intent=intent, best_query_type=best_query_type)
        
        memory_token_limit = to_get_memory_token_limit(context=context, query=query)

        prompt_context = build_prompt_context(session=session, context=context, query=query, memory_token_limit=memory_token_limit)
        
        response = get_response(prompt_context=prompt_context)
        print("CONTEXT: ", context)
        print("Assistant: ", response)

        return response, context


def ask_assistant_with_url_analysis(url_to_search):

    vt_attributes = search_virus_total(url_to_search)

    url_haus_attributes = url_haus(url_to_search)

    analysis = processing_attributes(url_analysis=vt_attributes, url_haus_result=url_haus_attributes, url_to_search=url_to_search)

    analysis_context = build_url_analysis_context(analysis=analysis)

    prompt_context = build_url_prompt(analysis_context=analysis_context)

    response = get_response(prompt_context=prompt_context)

    return response, analysis

def url_followup_questions(query, session, url_analysis):
    intent = understand_query_intent(query)

    ngrams = generate_n_grams(query)

    best_query_type = relationship_queries(query, intent=intent) #Overvoew, Relationship, General

    context_fuzzy = resolve_entity(query=query, intent=intent, best_query_type=best_query_type, entity_chunk=entity_chunk, ngrams=ngrams)

    if context_fuzzy:
        print("Context found through fuzzy matching. Using it to generate response.")

        prompt_context = build_url_followup_prompt(retrieved_context=context_fuzzy, analysis_context=url_analysis, user_query=query)
        response = get_response(prompt_context=prompt_context)
        
        print("Assistant: ", response)
        return response
    else:
        print("No relevant context found through fuzzy matching. Proceeding with FAISS-based approach.")
        retrieved_chunks = get_context(query=query, entity_chunk=entity_chunk)

        context = final_context(retrieved_chunks=retrieved_chunks, intent=intent, best_query_type=best_query_type)
        
        prompt_context = build_url_followup_prompt(retrieved_context=context, analysis_context=url_analysis, user_query=query)
        
        response = get_response(prompt_context=prompt_context)
        print("CONTEXT: ", context)
        print("Assistant: ", response)

        return response
