import json
import faiss
from sentence_transformers import SentenceTransformer
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import torch 
import os


with open("enterprise-attack-1.0.json", "r") as f:
    data = json.load(f)


for objects in data["objects"]:
    if objects["type"] == "attack-pattern":
        name = objects.get("name", "N/A")
        description = objects.get("description", "N/A")


        external_references = objects.get("external_references", [])
        for reference in external_references:
            if reference.get("source_name") == "mitre-attack":
                external_id = reference.get("external_id", "N/A")
            

all_chunks = []


all_chunks.append({
    "id": external_id,
    "text": f"""
        name: {name},
        description: {description}
    """
})



embedding_model = SentenceTransformer('all-MiniLM-L6-v2')


tokenizer = AutoTokenizer.from_pretrained("google/flan-t5-large")

model = AutoModelForSeq2SeqLM.from_pretrained("google/flan-t5-large")


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
def create_embeddings(all_chunks):

    texts = [
        chunk["text"]
        for chunk in all_chunks
    ]
    
    embeddings = embedding_model.encode(
        texts,
        convert_to_tensor=True,
        device = device
    )


    index = faiss.IndexFlatIP(embeddings.shape[1])

    embeddings_np = embeddings.cpu().numpy().astype("float32")

    faiss.normalize_L2(embeddings_np)

    index.add(embeddings_np)

    os.makedirs("indices", exist_ok=True)

    faiss.write_index(index, "indices/mitre_attack.index")

    return texts


def retrieve_context(query, all_chunks):
    query_embedding = embedding_model.encode(
        [query],
        convert_to_tensor= True,
        device = device
    )

    index = faiss.read_index("indices/mitre_attack.index")
    query_embedding_np = query_embedding.cpu().numpy().astype("float32")
    faiss.normalize_L2(query_embedding_np)

    distance, indices = index.search(query_embedding_np, k=3)
    
    retrieved_chunks = []

    for i in indices[0]:
        retrieved_chunks.append(
            all_chunks[i]
        )
    
    return retrieved_chunks


def get_context(retrieved_chunks):
    context = []

    for chunk in retrieved_chunks:
        context.append(
            f"""
            id: {chunk['id']},
            text: {chunk['text']}
            """
        )

    final_context = "\n\n".join(context)
    
    return final_context


def generate_response(query, context):
    prompt = f"""
    You are a cybersecurity assistant. Use the following context to answer the question.

    Context: {context}

    Question: {query}

    AI Response: 
    """

    input_ids = tokenizer(
        prompt,
        return_tensors = "pt",
    )
    input_ids = {key: value.to(device) for key, value in input_ids.items()}


    response_ids = model.generate(
        **input_ids,
        max_new_tokens = 200,
        repetition_penalty = 1.2,
        no_repeat_n_gram_size = 3
    )

    response = tokenizer.decode(
        response_ids[0],
        skip_special_tokens = True
    )

    return response





query = " what are Accessibility Features"

all_chunks = create_embeddings(all_chunks)
retrieved_chunks = retrieve_context(query, all_chunks)
context = get_context(retrieved_chunks)
response = generate_response(query, context)
print("Query:", query)
print("Response:", response)
