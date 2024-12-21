from kivy.uix.screenmanager import Screen
from kivy.uix.label import Label
from kivy.clock import Clock
from tinydb import TinyDB, Query

# Initialize TinyDB database
db = TinyDB('database/users.json')
User = Query()

class Login(Screen):

    def clear_fields(self):
        self.ids.username.text = ''
        self.ids.password.text = ''

    def login(self, username, password):
        # Check if the user exists and the password matches
        user = db.search(User.username == username)
        if user and user[0]['password'] == password:
            # Display success message and redirect to Home screen
            self.display_message("Login successful!", (0, 1, 0, 1))  # Green color
            Clock.schedule_once(lambda _: self.redirect_to_home(), 1.5)
        else:
            # Display error message for invalid credentials
            self.display_message("Invalid login credentials", (1, 0, 0, 1))  # Red color

    def display_message(self, message, color):
        # Create a label to display feedback
        feedback_label = Label(
            text=message,
            font_size="30sp",
            color=color,
            size_hint=(0.6, 0.2),
            pos_hint={"center_x": 0.65, "y": 0.8}
        )
        self.add_widget(feedback_label)

        # Remove the label after 3 seconds
        Clock.schedule_once(lambda _: self.remove_widget(feedback_label), 3)

    def redirect_to_home(self):
        # Redirect to the Home screen
        self.manager.current = "home"