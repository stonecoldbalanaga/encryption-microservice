
import jwt,datetime
from src.config.settings import JWT_SECRET
def generate_token(user):
    return jwt.encode({'sub':user,'exp':datetime.datetime.utcnow()+datetime.timedelta(hours=8)},JWT_SECRET,algorithm='HS256')
