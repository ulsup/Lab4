import hashlib


class User:
    def __init__(self, username, password):  # initializes User with a username and password
        '''
        Create a new user object. The password
        will be encrypted before storing.
        '''
        self.username = username  # refers to the created object's name
        self.password = self._encrypt_pw(password)
        self.is_logged_in = False  # there should not be any active sessions (user should be logged out on default)

    def _encrypt_pw(self, password):
        '''
        Encrypt the password with the username and return
        the sha digest.
        '''
        hash_string = (self.username + password)
        hash_string = hash_string.encode("utf8")
        return hashlib.sha256(hash_string).hexdigest()

    def check_password(self, password):
        '''
        Return True if the password is valid for this
        user, false otherwise.
        '''
        encrypted = self._encrypt_pw(password)
        return encrypted == self.password


class AuthException(Exception):  # extends Exception class
    def __init__(self, username, user=None):  # 'user' parameter  should be an instance of the User class
        # associated with that username
        super().__init__(username, user)  # super is used for multiple inheritance in parentheses
        # (e.g. UsernameAlreadyExists(AuthException))
        self.username = username
        self.user = user


class UsernameAlreadyExists(AuthException):
    '''
    Doesn't add a user if that username already exists in the dictionary. Otherwise it'll overwrite
    an existing user's data and the new user might have access to that user's info.
    '''
    pass


class PasswordTooShort(AuthException):
    '''
    The matter of security password to be longer than 6 symbols.
    '''
    pass


class InvalidUsername(AuthException):
    '''
    If username does not exist.
    '''
    pass


class InvalidPassword(AuthException):
    '''
    If password is incorrect.
    '''
    pass


class Authenticator:
    def __init__(self):
        '''Construct an authenticator to manage
        users logging in and out.'''
        self.users = {}  # creates s dictionary to add all users (and their passwords)

    def add_user(self, username, password):  # this method checks the existance of a username and the validation
        # of password (length)
        if username in self.users:
            raise UsernameAlreadyExists(username)
        if len(password) < 6:
            raise PasswordTooShort(username)
        self.users[username] = User(username, password)  # if it does not raise any exceptions, method creates new user

    def login(self, username, password):
        try:
            user = self.users[username]
        except KeyError:
            raise InvalidUsername(username)
        if not user.check_password(password):
            raise InvalidPassword(username, user)
        user.is_logged_in = True  # if class doesn't raise these exceptions, it flags the user as logged in
        # and returns True
        return True

    def is_logged_in(self, username):
        '''
        Checks if User is already logged in.
        '''
        if username in self.users:
            return self.users[username].is_logged_in
        return False


authenticator = Authenticator()


class PermissionError(Exception):
    pass


class NotLoggedInError(AuthException):
    '''
    If not logged in.
    '''
    pass


class NotPermittedError(AuthException):
    '''
    If there is no permission.
    '''
    pass


class Authorizor:
    def __init__(self, authenticator):
        self.authenticator = authenticator  # refers to authenticator which permits a user access if logged in
        self.permissions = {}  # permission dictionary

    def add_permission(self, perm_name):
        '''
        Creates a new permission that users
        can be added to.
        '''
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:  # if permission already exists, an exception is raised
            self.permissions[perm_name] = set()  # uses set to store unique values
        else:
            raise PermissionError("Permission Exists")

    def permit_user(self, perm_name, username):
        '''
        Grants the given permission to the user.
        '''
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            raise PermissionError("Permission does not exist")
        else:
            if username not in self.authenticator.users:  # if the name isn't registered, an exception is raised
                raise InvalidUsername(username)
            perm_set.add(username)  # adds a permission to a set

    def check_permission(self, perm_name, username):
        '''
        Checks whether a user has a specific permission or not.
        '''
        if not self.authenticator.is_logged_in(username):  # checks if the user is logged in
            raise NotLoggedInError(username)
        try:
            perm_set = self.permissions[perm_name]  # finds permission (if no - raises exception)
        except KeyError:
            raise PermissionError("Permission does not exist")
        else:
            if username not in perm_set:
                raise NotPermittedError(username)
            else:
                return True


authorizor = Authorizor(authenticator)
