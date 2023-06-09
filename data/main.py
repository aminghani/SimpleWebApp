import crud, models, schemas
from database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db = SessionLocal()

db_user = crud.get_all_usernames(db)
print(db_user)
