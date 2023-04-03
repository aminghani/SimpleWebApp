import data.crud as cd
from data.database import SessionLocal

db = SessionLocal()
print(cd.get_all_users(db))