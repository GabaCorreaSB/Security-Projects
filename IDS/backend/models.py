from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./ids.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()

SessionLocal = sessionmaker(autocomit=False, autoflush=False, bind=engine)

class SuspiciousAttempt(Base):
    __tablename__ = "suspicious_attempts"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)
    count = Column(DateTime)
    end_time = Column(DateTime)