from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base
from src.database import engine

Base = declarative_base()

class SecretModel(Base):
    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    hash = Column(String)
    algorithm = Column(String)

Base.metadata.create_all(bind=engine)
