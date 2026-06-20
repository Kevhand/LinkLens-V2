from sentence_transformers import SentenceTransformer



embedding_model = None

def get_embedding_model():
    global embedding_model
    print("Loading embedding model...")

    if embedding_model is None:
        embedding_model = SentenceTransformer(
            "all-MiniLM-L6-v2"
        )

    print("Embedding model loaded.")
    return embedding_model
