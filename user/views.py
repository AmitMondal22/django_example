from django.shortcuts import render ,redirect
from user.models import User
from django.contrib.auth import authenticate, login, logout
# from django.core import serializers
import bcrypt
# import json


def convert_json(data):
    data_dict = data.__dict__.copy()

    # Exclude non-serializable elements (e.g., ModelState)
    if '_state' in data_dict:
        del data_dict['_state']

    return data_dict

# Create your views here.
def register_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        g_salt=bcrypt.gensalt()
        password = bcrypt.hashpw(password.encode('utf-8'), g_salt).decode('utf-8')
        
        User.objects.create(name=name, email=email, password=password)
        
        print(name,email,password)
        return redirect('/login')
    else:
        return render(request, 'user/register.html')

def login_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        # user = User.objects.get(email=email)
        user = User.objects.filter(email=email).first()
        if user:
            db_password = user.password
            if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            # if authenticate(request, email=email, password=password):

                # Set a session value
                request.session['session_key'] = convert_json(user)
                # request.session['session_key'] = user.values()
                
                print(request.session['session_key']['name'])

                # Delete a session value
                # del request.session['session_key']
                
                
                print('login successful')
                login(request, user)
                return redirect('/home')
            else:
                return redirect('/login2')
        else:
            return redirect('/login2')
    else:
        return render(request, 'user/login.html')
    
    
def home_page(request):
    print(request.session['session_key']['name'])
    return render(request, 'user/home.html')
    
    