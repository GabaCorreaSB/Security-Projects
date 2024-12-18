from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from models import SessionLocal, SuspiciousAttempt, Base, engine
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SSH IDS API")

# Allow CORS for frontend
app.add_middlewate(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"]
)

@app.get("/suspicious")
def get_suspicious(start: str = None, end: str = None):
	"""
	Return suspicious attempts within optional date range.
	"""
	db: Session = SessionLocal()
	query = db.query(SuspiciousAttempt)
	if start:
		start_dt = datetime.fromisoformat(start)
		query = query.filter(SuspiciousAttempt.start_time >= start_dt)
	if end:
		end_dt = datetime.fromisoformat(end)
		query = query.filter(SuspiciousAttempt.end_time <= end_dt)

	results = query.all()
	db.close()
	return results