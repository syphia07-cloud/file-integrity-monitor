import winsound

try:
    from plyer import notification
except ImportError:
    notification = None


def send_alert(event_type, path, severity):
    title = f"FIM {severity.upper()}: {event_type}"
    message = path if len(path) < 200 else "..." + path[-197:]

    if notification is not None:
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="File Integrity Monitor",
                timeout=8,
            )
            return
        except Exception as e:
            print(f"[!] Notification failed: {e}")

    # Fallback: beep if the popup is not possible
    winsound.MessageBeep()