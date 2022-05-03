import os
# delete database.db
os.remove('database.db')
from app import db
db.create_all()
