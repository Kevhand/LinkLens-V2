from django.shortcuts import redirect, render, get_object_or_404
from assistant.assistant import ask_assistant, ask_assistant_with_url_analysis, url_followup_questions
from assistant.retreival import processing_attributes
from django.contrib.auth import authenticate, login, logout
from .models import User, ChatSession, Message, ChatSummary, URLAnalysis
import uuid

# Create your views here.



def register(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')


        if password1 != password2:
            return render(request, 'assistant/register.html', {'error': 'Passwords do not match.'})
        if len(password1) < 8:
            return render(request, 'assistant/register.html', {'error': 'Password must be at least 8 characters long.'})

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            return render(request, 'assistant/register.html', {'error': 'Username already exists.'})
        
        # Create new user
        user = User.objects.create_user(username=username, email=email, password=password1)
        user.save()
        
        return render(request, 'assistant/register.html', {'message': 'User registered successfully. Please log in.'})
    return render(request, 'assistant/register.html')


def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return render(request, 'assistant/home.html', {'message': 'Logged in successfully.'})   
        else:
            return render(request, 'assistant/login.html', {'error': 'Invalid username or password.'})

    return render(request, 'assistant/login.html')

def logout_view(request):
    logout(request)
    return render(request, 'assistant/login.html', {'message': 'Logged out successfully.'})



def home(request):
    if request.user.is_authenticated:
        chat_sessions = ChatSession.objects.filter(
            user = request.user,
            chat_type = "assistant"
        )

        url_analysis_sessions = ChatSession.objects.filter(
            user = request.user,
            chat_type = "url_analysis"
        )


        return render(request, 'assistant/home.html',{
            "chat_sessions": chat_sessions,
            "url_analysis_sessions": url_analysis_sessions
        })
    else:
        return render(request, 'assistant/home.html', {
            "message": "Welcome to the AI Assistant! Please log in to start chatting."
        })

def send_message(request):
    if request.method == "POST":
       if request.user.is_authenticated:
           query = request.POST.get('query', "").strip()
           if query:
               title = query[:50] + "..." if len(query) > 50 else query
               session_id = request.POST.get('session_id')
               print("SESSION ID:", repr(session_id))
               if not session_id:
                   session = ChatSession.objects.create(
                       session_id=str(uuid.uuid4()),
                       user=request.user,
                       title=title
                   )
               else:
                   session = ChatSession.objects.get(session_id=session_id, user=request.user)
               Message.objects.create(
                   session=session,
                   role='user',
                   content=query
               )
               response = ask_assistant(query=query, session=session)
               Message.objects.create(
                   session= session,
                   role='assistant',
                   content=response
               )
               messages = session.messages.all()
               return render(request, 'assistant/chat.html', {
                   'response': response,
                   'query': query,
                   'messages': messages,
                   'session_id': session.session_id
               })


def new_chat(request):
    if request.user.is_authenticated:
        return render(request, 'assistant/chat.html', {
            'message': 'New chat session created.',
            'messages': [],
            'session_id': '',

        })
    else:
        return render(request, 'assistant/home.html', {
            "message": "Please log in to start a new chat session."
        })
     

def chat_details(request, session_id):
    if request.user.is_authenticated:
        session = get_object_or_404(ChatSession, session_id=session_id, user=request.user)
        messages = session.messages.all()
        return render(request, 'assistant/chat.html', {
            'messages': messages,
            'session_id': session.session_id
            })
    else:
        return render(request, 'assistant/home.html', {
            "message": "Please log in to view chat sessions."
        })

def delete_chat_session(request, session_id):
    if request.user.is_authenticated:
        session = get_object_or_404(ChatSession, session_id=session_id, user=request.user)
        session.delete()
    return redirect('home')



def scan_url(request):
    if request.user.is_authenticated:
        return render(request, 'assistant/scan_url.html', {
            'message': [],
            'session_id': '',
        })
    else:
        return render(request, 'assistant/home.html', {
            "message": "Please log in to scan URLs."
        })


def submit_url(request):
    print("submit url called")
    if request.method == "POST":
        if request.user.is_authenticated:
            url_to_search = request.POST.get('url_to_search', "").strip()

            if url_to_search:
                title = url_to_search[:50] + "..." if len(url_to_search) > 50 else url_to_search
                session_id = request.POST.get('session_id')

                if not session_id:
                    session = ChatSession.objects.create(
                        session_id = str(uuid.uuid4()),
                        user=request.user,
                        title=title,
                        chat_type="url_analysis"
                    )
                else:
                    session = ChatSession.objects.get(session_id=session_id, user=request.user)
                
                Message.objects.create(
                    session=session,
                    role='user',
                    content=url_to_search
                )

                response, analysis = ask_assistant_with_url_analysis(url_to_search=url_to_search)

                Message.objects.create(
                    session=session,
                    role='assistant',
                    content=response
                )

                URLAnalysis.objects.create(
                    session=session,
                    url=url_to_search,
                    analysis_result=analysis
                )
                messages = session.messages.all()
                return render(request, 'assistant/scan_url.html', {
                    'response': response,
                    'url_to_search': url_to_search,
                    'messages': messages,
                    'session_id': session.session_id
                })


def url_followup_questions_view(request, session_id):
    if request.method == "POST": 
        if request.user.is_authenticated:
            query = request.POST.get("query", "").strip()
            session = get_object_or_404(ChatSession, session_id=session_id, user=request.user, chat_type="url_analysis")
            url_analysis = session.url_analysis.analysis_result
           
            Message.objects.create(
                session = session,
                role = "user",
                content = query
            )
            response = url_followup_questions(query=query, session=session, url_analysis=url_analysis)
            Message.objects.create(
                session = session,
                role = "assistant",
                content = response
            )
            messages = session.messages.all()
            return render(request, 'assistant/scan_url.html', {
                'response': response,
                'query': query,
                'messages': messages,
                'session_id': session.session_id
            })
        

