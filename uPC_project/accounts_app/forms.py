from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserChangeForm, UserCreationForm
from django.contrib.auth.forms import SetPasswordForm, PasswordChangeForm

from .models import User
from django.contrib.auth import get_user_model

from django.contrib.auth.hashers import check_password


# 회원가입 폼
class SignupForm(UserCreationForm):
    def __init__(self, *args, **kwargs):
        super(SignupForm, self).__init__(*args, **kwargs)

        self.fields['username'].label = '아이디'
        self.fields['username'].widget.attrs.update({
            'class' : 'form-control',
            'autofocus' : False,
            'placeholder' : '아이디를 입력해주세요',
        })
        self.fields['password1'].label = '비밀번호'
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': '비밀번호를 입력해주세요',
        })
        self.fields['password2'].label = '비밀번호 확인'
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': '비밀번호를 다시 입력해주세요',
        })
        self.fields['email'].label = '이메일'
        self.fields['email'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': '회원가입 후 입력하신 메일로 본인인증 메일이 전송됩니다',
        })
        self.fields['name'].label = '이름'
        self.fields['name'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': "아이디, 비밀번호 찾기에 이용됩니다",
        })
    
    class Meta:
        model = User
        fields = ['username', 'password1', 'password2', 'email', 'name']

    def save(self, commit=True):
        user = super(SignupForm, self).save(commit=False)
        user.is_active = False
        user.save()
        return user


# 로그인 폼
class LoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class':'form-control'}),
        error_messages={'required':'이메일을 입력해주세요'},
        label='이메일')
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class':'form-control'}),
        error_messages={'required':'비밀번호를 입력해주세요'},
        label='비밀번호')
    
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        if email and password:
            try:
                user = User.objects.get(email = email)
            except User.DoesNotExist:
                self.add_error('email', 'email이 존재하지 않습니다.')
                return
        if not check_password(password, user.password):
            self.add_error('password', '비밀번호가 틀렸습니다')        
        

# 회원정보 수정 폼
class CustomUserChangeForm(UserChangeForm):
    name = forms.CharField(label='이름', widget=forms.TextInput(
        attrs={'class': 'form-control', 'maxlength':'20',}), ) 
    class Meta:
        model = get_user_model()
        fields = ['username', 'name']

    def clean_username(self):
        username = self.cleaned_data.get('username')
        user_model = get_user_model()     
        # 중복 체크
        if user_model.objects.filter(username=username).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError('이미 사용 중인 아이디입니다.')   
        return username


# 회원탈퇴 비밀번호확인 폼
class CheckPasswordForm(forms.Form):
    password = forms.CharField(label='비밀번호', widget=forms.PasswordInput(
        attrs={'class': 'form-control',}), 
    )
    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = self.user.password
        
        if password:
            if not check_password(password, confirm_password):
                self.add_error('password', '비밀번호가 일치하지 않습니다.')


# 비밀번호 찾기 폼
class RecoveryPwForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput,)
    name = forms.CharField(widget=forms.TextInput,)
    email = forms.EmailField(widget=forms.EmailInput,)

    class Meta:
        fields = ['username', 'name', 'email']

    def __init__(self, *args, **kwargs):
        super(RecoveryPwForm, self).__init__(*args, **kwargs)
        self.fields['username'].label = '아이디'
        self.fields['username'].widget.attrs.update({
            'placeholder': '아이디를 입력해주세요',
            'class': 'form-control',
            'id': 'pw_form_id',
        })
        self.fields['name'].label = '이름'
        self.fields['name'].widget.attrs.update({
            'placeholder': '이름을 입력해주세요',
            'class': 'form-control',
            'id': 'pw_form_name',
        })
        self.fields['email'].label = '이메일'
        self.fields['email'].widget.attrs.update({
            'placeholder': '이메일을 입력해주세요',
            'class': 'form-control',
            'id': 'pw_form_email',
        })


# 비밀번호찾기 새 비밀번호 입력 폼
class CustomSetPasswordForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super(CustomSetPasswordForm, self).__init__(*args, **kwargs)
        self.fields['new_password1'].label = '새 비밀번호'
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': '새 비밀번호',
        })
        self.fields['new_password2'].label = '새 비밀번호 확인'
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': '새 비밀번호 확인',
        })


# 비밀번호 변경 폼
class CustomPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super(CustomPasswordChangeForm, self).__init__(*args, **kwargs)
        self.fields['old_password'].label = '기존 비밀번호'
        self.fields['old_password'].widget.attrs.update({
            'class': 'form-control',
            'autofocus': False,
            'style': 'margin-top:-15px;'
        })
        self.fields['new_password1'].label = '새 비밀번호'
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
        })
        self.fields['new_password2'].label = '새 비밀번호 확인'
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control',
        })