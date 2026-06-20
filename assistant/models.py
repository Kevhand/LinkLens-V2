from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class ChatSession(models.Model):
    CHAT_TYPES = [
        ("assistant", "Assistant"),
        ("user", "User"),
        ("url_analysis", "URL Analysis"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    session_id = models.CharField(max_length=255, unique=True, editable=False)

    chat_type = models.CharField(max_length=20, choices=CHAT_TYPES, default="assistant")

    title = models.CharField(max_length=255, default="New Chat Session")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Session {self.session_id} for {self.user.username}"

class Message(models.Model):
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='messages')
    
    role = models.CharField(max_length=10, choices=[('user', 'User'), ('assistant', 'Assistant')])
    
    content = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']


class ChatSummary(models.Model):
    session = models.OneToOneField(
        ChatSession,
        on_delete=models.CASCADE,
        related_name="summary"
    )
    
    summary = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_message_id = models.IntegerField(default=0)



class URLAnalysis(models.Model):
    session = models.OneToOneField(
        ChatSession,
        on_delete=models.CASCADE,
        related_name="url_analysis"
    )
    
    url = models.URLField()
    
    analysis_result = models.JSONField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)