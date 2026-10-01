"""Runs the app on this computer for trying it out: python -m secure_login"""

import argparse
import threading
import webbrowser

from . import create_app


def main():
    parser = argparse.ArgumentParser(
        prog="secure_login", description="Run the Secure Login demo on this computer."
    )
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--open", action="store_true", help="open the app in the browser")
    args = parser.parse_args()
    url = f"http://127.0.0.1:{args.port}"

    # Plain HTTP is acceptable only because the server listens on the
    # loopback address, which other machines cannot reach. The cookie's
    # Secure flag has to be off for the browser to send it back over HTTP.
    app = create_app({"SESSION_COOKIE_SECURE": False})
    print(f"Secure Login is running at {url}  (Ctrl+C to stop)")
    print("Local use only. See the README before putting it on a network.")
    if args.open:
        threading.Timer(1.0, webbrowser.open, [url]).start()
    # The debugger is never enabled: it lets anyone who reaches it run code.
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
