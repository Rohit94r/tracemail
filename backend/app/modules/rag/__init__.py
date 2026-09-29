"""SIH26159 SecureMailScope — grounded RAG (retrieval + cite-or-refuse)."""

from .retriever import Retriever, Span, build_corpus, retrieve
from .generator import answer

__all__ = ["Retriever", "Span", "build_corpus", "retrieve", "answer"]
