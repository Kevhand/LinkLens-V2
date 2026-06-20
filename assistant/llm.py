from transformers import AutoTokenizer, AutoModelForCausalLM, AutoModelForSeq2SeqLM
import torch
import os
import re
from sentence_transformers import SentenceTransformer


model = None
device = None
tokenizer = None

tokenizer_summarizer = None
model_summarizer = None

def get_device():
    global device

    print("Loading device...")

    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


    print("Device loaded.")
    return device


def get_tokenizer():
    global tokenizer

    print("Loading tokenizer...")
    if tokenizer is None:
        tokenizer = AutoTokenizer.from_pretrained(
            "Qwen/Qwen2.5-1.5B-Instruct"
        )

    print("Tokenizer loaded.")
    return tokenizer



def get_llm():
    global model

    print("Loading model...")
    if model is None:
        model = AutoModelForCausalLM.from_pretrained(
            "Qwen/Qwen2.5-1.5B-Instruct",
            low_cpu_mem_usage=True
        )

        model.to(get_device())

    print("Model loaded.")
    return model


def get_summarizer():
    print("Loading Summarizer...")
    global tokenizer_summarizer, model_summarizer

    if tokenizer_summarizer is None:
        tokenizer_summarizer = AutoTokenizer.from_pretrained("facebook/bart-large-cnn")

    if model_summarizer is None:
        model_summarizer = AutoModelForSeq2SeqLM.from_pretrained("facebook/bart-large-cnn")

    print("Summarizer loaded.")
    return tokenizer_summarizer, model_summarizer
