import time
from ids_detector import store_suspicious

# simple scheduler: In production, consider cron
if __name__ == "__main__":
	while True:
		store_suspicious()
		time.sleep(600) # Every 10 minutes