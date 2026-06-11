
from flask_httpauth import HTTPBasicAuth
from src.config.settings import BASIC_USER,BASIC_PASSWORD
auth=HTTPBasicAuth()
@auth.verify_password
def verify(username,password):
    return username if username==BASIC_USER and password==BASIC_PASSWORD else None
