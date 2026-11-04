import sys


def run():
    while True:
        print("\nPassword manager")
        print("1. Register")
        print("2. Log in")
        print("3. Exit")
        choice = input("Choice: ")

        if choice == "1":
            print("Registration is not implemented yet.")
        elif choice == "2":
            print("Login is not implemented yet.")
        elif choice == "3":
            return
        else:
            print("Choose 1, 2, or 3.")


def main() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Run this application in an interactive terminal.")
        return 1

    try:
        run()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
