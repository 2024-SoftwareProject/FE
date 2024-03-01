# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'mydatabase', # mydatabase
        'USER': 'root', # mydatabaseuser
        'PASSWORD': 'soft1234', # mypassword
        'HOST': 'localhost', # host
        'PORT': '3306',
    }
}

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-7+1muv^0)9%#-_o@vb4152b$pf!x$*do3e!3x45m1fwa@^^qt8'

# Email smtp
EMAIL_HOST_PASSWORD = 'thdnp@1004'