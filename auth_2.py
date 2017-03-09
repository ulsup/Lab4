import auth

auth.authenticator.add_user("joe", "joepassword")
auth.authorizor.add_permission("test program")
auth.authorizor.add_permission("change program")
auth.authorizor.permit_user("test program", "joe")


class Editor:
    def __init__(self):
        self.username = None
        self.menu_map = {
            "sign up": self.sign,
            "login": self.login,
            "test": self.test,
            "change": self.change,
            "quit": self.quit
        }

    def sign(self):
        signed_up = False
        username = input("username: ")
        password = input("password: ")
        try:
            signed_up = auth.authenticator.add_user(username, password)
        except auth.UsernameAlreadyExists:
            print("Sorry, that username already exists.")
        except auth.PasswordTooShort:
            print("Sorry, your password too short (should be more than 6 symbols).")
        else:
            self.username = username

    def login(self):
        logged_in = False
        while not logged_in:
            username = input("username: ")
            password = input("password: ")
            try:
                logged_in = auth.authenticator.login(username, password)
            except auth.InvalidUsername:
                print("Sorry, that username does not exist")
            except auth.InvalidPassword:
                print("Sorry, incorrect password")
            else:
                self.username = username

    def is_permitted(self, permission):
        try:
            auth.authorizor.check_permission(
                permission, self.username)
        except auth.NotLoggedInError as e:
            print("{} is not logged in".format(e.username))
            return False
        except auth.NotPermittedError as e:
            print("{} cannot {}".format(
                e.username, permission))
            return False
        else:
            return True

    def test(self):
        if self.is_permitted("test program"):
            print("Testing program now...")

    def change(self):
        if self.is_permitted("change program"):
            print("Changing program now...")

    def quit(self):
        raise SystemExit()

    def menu(self):
        try:
            answer = ""
            while True:
                print("""                         =========================
                          Please enter a command:
                         =========================
                       \tsign up\tSign up
                       \tlogin\tLogin
                       \ttest\tTest the program
                       \tchange\tChange the program
                       \tquit\tQuit
                """)
                answer = input("Enter a command: ").lower()
                try:
                    func = self.menu_map[answer]
                except KeyError:
                    print("{} is not a valid option".format(
                        answer))
                else:
                    func()
        finally:
            print("Thank you for testing the auth module")


Editor().menu()
