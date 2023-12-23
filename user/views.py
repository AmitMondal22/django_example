from django.shortcuts import render ,redirect
from user.models import User
import bcrypt

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

def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        # user = User.objects.get(email=email)
        user = User.objects.filter(email=email).first()
        if user:
            db_password = user.password
            if bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
                print('login successful')
                return redirect('/login')
            else:
                return redirect('/login2')
        else:
            return redirect('/login2')
    else:
        return render(request, 'user/login.html')
    
    