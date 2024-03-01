from django.conf import settings

from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth import login, logout
from django.contrib.auth import authenticate, update_session_auth_hash
from django import forms
from django.views.generic import CreateView, FormView, TemplateView
from django.views.generic import View

from django.contrib.auth.forms import UserChangeForm
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model

from django.contrib import messages
from django.urls import reverse
from django.urls import reverse_lazy
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponse
import json
from django.core.serializers.json import DjangoJSONEncoder

from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError

from .models import User
from .forms import SignupForm, LoginForm
from .forms import CustomUserChangeForm, CheckPasswordForm
from .forms import RecoveryPwForm
from .forms import CustomPasswordChangeForm, CustomSetPasswordForm

from .helper import send_mail, email_auth_num
from .decorators import login_message_required, admin_required, logout_message_required
from django.utils.decorators import method_decorator

# Create your views here.


# 회원가입 인증메일 발송 안내 창
def Signup_success(request):
    if not request.session.get('signup_auth', False):
        raise PermissionDenied
    request.session['signup_auth'] = False
    return render(request, 'accounts/signup_success.html')


# 회원가입 약관동의
@method_decorator(logout_message_required, name='dispatch')
class Agreement(View):
    def get(self, request, *args, **kwargs):
        request.session['agreement'] = False
        return render(request, 'accounts/agreement.html')
    def post(self, request, *args, **kwarg):
        if request.POST.get('agreement1', False) and request.POST.get('agreement2', False):
            request.session['agreement'] = True
            return redirect('signup')
        else:
            messages.info(request, "약관에 모두 동의해주세요.")
            return render(request, 'accounts/agreement.html')  
    

# 회원가입
class Signup(CreateView):
    model = User
    template_name = 'accounts/signup.html'
    form_class = SignupForm

    def get(self, request, *args, **kwargs):
        if not request.session.get('agreement', False):
            return redirect('agreement')
        request.session['agreement'] = False
    
        if request.user.is_authenticated:
            return redirect('home')
        
        # 조건에 맞지 않을 때 어떤 HttpResponse 객체를 반환할지 지정
        return super().get(request, *args, **kwargs)
        
    def get_success_url(self):
        self.request.session['signup_auth'] = True
        messages.success(self.request, '회원님의 입력한 Email 주소로 인증 메일이 발송되었습니다. 인증 후 로그인이 가능합니다')
        return reverse('signup_success')
    
    def form_valid(self, form):
        self.object = form.save()

        send_mail(
            '[uPC] {}님의 회원가입 인증메일 입니다.'.format(self.object.username),
            [self.object.email],
            html = render_to_string('accounts/signup_email.html',{
                'user':self.object,
                'uid': urlsafe_base64_encode(force_bytes(self.object.pk)).encode().decode(),
                'domain': self.request.META['HTTP_HOST'],
                'token': default_token_generator.make_token(self.object),
            }),
        )
        return redirect(self.get_success_url())


# 로그인
@method_decorator(logout_message_required, name='dispatch')
class Login(FormView):
    template_name = 'accounts/login.html'
    form_class = LoginForm
    success_url = '/'

    def form_valid(self, form):
        email = form.cleaned_data.get("email")
        password = form.cleaned_data.get("password")

        user = authenticate(self.request, email=email, password=password)
        if user is not None:
            self.request.session['email'] = email
            login(self.request, user)

            remember_session = self.request.POST.get('remember_session',False)
            if remember_session:
                settings.SESSION_EXPIRE_AT_BROWSER_CLOSE = False
        return super().form_valid(form)


# 로그아웃
@require_POST
def Logout(request):
    logout(request)
    return redirect('home')


# 마이페이지
@login_message_required
def Mypage(request):
    if request.method == 'GET':
        return render(request, 'accounts/mypage.html')    


# 계정 수정
@login_message_required
def editAccount(request):
    if request.method == 'POST':
        user_change_form = CustomUserChangeForm(request.POST, instance=request.user)

        if user_change_form.is_valid():
            user_change_form.save()
            messages.success(request, '회원정보가 수정되었습니다')
            return redirect('mypage')
        
    else:
        user_change_form = CustomUserChangeForm(instance=request.user)

    context = {'user_change_form':user_change_form}
    return render(request, 'accounts/edit_account.html', context)


# 비밀번호 수정
@login_message_required
def editPassword(request):
    if request.method == 'POST':
        password_change_form = CustomPasswordChangeForm(request.user, request.POST)

        if password_change_form.is_valid():
            user = password_change_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, '비밀번호가 성공적으로 변경되었습니다')
            return redirect('mypage')
        
    else:
        password_change_form = CustomPasswordChangeForm(request.user)

    context = {'password_change_form':password_change_form}
    return render(request, 'accounts/edit_password.html', context)


# 회원탈퇴
@login_message_required
def deleteAccount(request):
    if request.method == 'POST':
        password_form = CheckPasswordForm(request.user, request.POST)

        if password_form.is_valid():
            request.user.delete()
            logout(request)
            messages.success(request, "회원탈퇴가 완료되었습니다.")
            return redirect('home')
    else :
        password_form = CheckPasswordForm(request.user)
    return render(request, 'accounts/delete_account.html', {'password_form':password_form})


# 비밀번호 찾기
@method_decorator(logout_message_required, name='dispatch')
class recoveryPW(View):
    template_name = 'accounts/recovery_pw.html'
    recovery_pw = RecoveryPwForm

    def get(self, request):
        if request.method == 'GET':
            form_pw = self.recovery_pw(None)
            return render(request, self.template_name, {'form_pw':form_pw})


# 비밀번호 AJAX 통신
def ajax_find_pw(request):
    username = request.POST.get('username')
    name = request.POST.get('name')
    email = request.POST.get('email')
    result_pw = User.objects.get(username=username, name=name, email=email)

    if result_pw:
        auth_num = email_auth_num()
        result_pw.auth = auth_num
        result_pw.save()
        send_mail(
            '[uPC] 비밀번호 찾기 인증 메일입니다',
            [email],
            html=render_to_string('accounts/recovery_pw_email.html',{
                'auth_num' : auth_num,
            }))
    return HttpResponse(json.dumps({"result":result_pw.username}, cls=DjangoJSONEncoder),
        content_type="application/json")


# 비밀번호 찾기 인증번호 확인
def auth_confirm(request):
    username = request.POST.get('username')
    input_auth_num = request.POST.get('input_auth_num')
    user = User.objects.get(username=username, auth=input_auth_num)
    user.auth = ""
    user.save()
    request.session['auth'] = user.username
    return HttpResponse(json.dumps(
        {"result":user.username}, cls=DjangoJSONEncoder),
        content_type ="application/json")


# 비밀번호 찾기 새 비밀번호 등록
@ logout_message_required
def auth_pw_reset(request):
    if request.method == "GET":
        if not request.session.get('auth',False):
            raise PermissionDenied
        
    if request.method == "POST":
        session_user = request.session['auth']
        current_user = User.objects.get(username=session_user)
        login(request, current_user)

        reset_password_form = CustomSetPasswordForm(request.user, request.POST)

        if reset_password_form.is_valid():
            user = reset_password_form.save()
            messages.success(request, "비밀번호 변경완료! 변경된 비밀번호로 로그인하세요")
            logout(request)
            return redirect('accounts:login')
        else:
            logout(request)
            request.session['auth'] = session_user
    else:
        reset_password_form = CustomSetPasswordForm(request.user)

    return render(request, 'accounts/password_reset.html', {'form':reset_password_form})


# 이메일 인증 활성화
def activate(request, uid64, token):
    try:
        uid = urlsafe_base64_decode(uid64).decode('utf-8')
        current_user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
        messages.error(request, '메일 인증에 실패했습니다.')
        return redirect('login')

    if default_token_generator.check_token(current_user, token):
        current_user.is_active = True
        current_user.save()

        messages.info(request, '메일 인증이 완료 되었습니다. 회원가입을 축하드립니다!')
        return redirect('login')

    messages.error(request, '메일 인증에 실패했습니다.')
    return redirect('login')


