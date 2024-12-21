from kivy.app import App
from screens.login import Login
from screens.register import Register
from screens.home import Home
from kivy.uix.screenmanager import ScreenManager

class ManageWindows(ScreenManager):
    pass

class MyVPNApp(App):
    def build(self):
        sm = ManageWindows()
        sm.add_widget(Login(name="login"))
        sm.add_widget(Register(name="register"))
        sm.add_widget(Home(name="home"))
        return sm

if __name__ == "__main__":
    MyVPNApp().run()
