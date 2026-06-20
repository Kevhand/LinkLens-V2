from django.urls import path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('chat/', views.new_chat, name='new_chat'),
    path('chat/<str:session_id>/', views.chat_details, name='chat'),
    path('chat/<str:session_id>/delete', views.delete_chat_session, name='delete_chat_session'),
    path('chat_details/<str:session_id>/', views.chat_details, name='chat_details'),
    path('send_message/', views.send_message, name='send_message'),

    #For URL
    path('scan_url/', views.scan_url, name='scan_url'),
    path('submit_url/', views.submit_url, name='submit_url'),
    path('url_followup_questions/<str:session_id>/', views.url_followup_questions_view, name='url_followup_questions'),
]