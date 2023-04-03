from sqlalchemy.orm import Session

from . import models, schemas


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_all_usernames(db: Session):
    return [user.username for user in db.query(models.User).all()]


def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def create_user(db: Session, user: schemas.User):
    hashed_password = user.hashed_password
    db_user = models.User(username=user.username, full_name=user.username,
                          email=user.email, hashed_password=hashed_password, disabled=user.disabled)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def change_full_name_and_email_by_username(db: Session, username: str,
                                           new_full_name: str, new_email: str):
    user = db.query(models.User).filter_by(username=username).first()
    user.email = new_email
    user.full_name = new_full_name
    db.commit()
    return user


def change_password_by_username(db: Session, username: str, new_password: str):
    user = db.query(models.User).filter_by(username=username).first()
    user.hashed_password = new_password
    db.commit()
    return user


def get_all_users(db: Session):
    result = db.query(models.User).all()
    return result
