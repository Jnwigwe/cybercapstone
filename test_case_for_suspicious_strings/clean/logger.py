import logging
import datetime

def log_event(event):
    timestamp = datetime.datetime.now()
    with open("/var/log/app.log", "a") as f:
        f.write(f"{timestamp}: {event}\n")

def main():
    log_event("Application started")
    print("Logging system initialized")

if __name__ == "__main__":
    main()
