from kivy.clock import Clock
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen
from tinydb import TinyDB, Query

# Initialize TinyDB database
db = TinyDB('database/users.json')
User = Query()

class Register(Screen):

    def register(self, username, password):

        if db.search(User.username == username) and len(password) < 8:
            self.display_message("Username already exists & Password must be a minimum of 8 characters", (1, 0, 0, 1))  # Red color
        
        elif len(username) == 0 and len(password) == 0:
            self.display_message("Username field cannot be empty & Password must be a minimum of 8 characters", (1, 0, 0, 1))  # Red color

        elif len(username) == 0:
            self.display_message("Username field cannot be empty", (1, 0, 0, 1))  # Red color

        elif db.search(User.username == username):
            self.display_message("Username already exists!", (1, 0, 0, 1))  # Red color

        elif len(password) < 8:
            self.display_message("Password must be at least 8 characters!", (1, 0, 0, 1))  # Red color

        else:
            # Save user credentials in TinyDB
            db.insert({'username': username, 'password': password})
            self.display_message("Registration successful!", (0, 1, 0, 1))  # Green color
            # Redirect to the login screen after 3 seconds
            Clock.schedule_once(lambda _: self.redirect_to_login(), 2)

    def display_message(self, message, color):
        # Create a label to display feedback
        feedback_label = Label(
            text=message,
            font_size="20sp",
            color=color,
            size_hint=(0.6, 0.1),
            pos_hint={"center_x": 0.65, "y": 0.85}
        )
        self.add_widget(feedback_label)

        # Remove the label after 3 seconds
        Clock.schedule_once(lambda _: self.remove_widget(feedback_label), 3)

    def redirect_to_login(self):
        self.manager.current = "login"
