from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.image import Image
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
import hashlib
from argon2 import PasswordHasher
import bcrypt
import os


class ScreenOne(Screen):
    def __init__(self, **kwargs):
        super(ScreenOne, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical')
        
        # Labela teksta
        self.label = Label(text="Dobro došli u aplikaciju za izradu hash-ova", font_size=42)
        layout.add_widget(self.label)

        # Slika
        image = Image(source="unnamed.png", size_hint=(None, None), size=(600, 600), pos_hint={"center_x": 0.5, "center_y": 0.5})
        layout.add_widget(image)



        # Gumb za prelazak na drugu stranicu
        next_button = Button(text="Idi na odabir datoteka", background_color=(1, 0, 0, 1), size_hint=(1, 0.2))
        next_button.bind(on_press=self.go_to_file_screen)
        layout.add_widget(next_button)

        # Gumb za zatvaranje aplikacije
        close_button = Button(text="Zatvori aplikaciju", background_color=(1, 0, 0, 1), size_hint=(1, 0.2))
        close_button.bind(on_press=self.close_app)
        layout.add_widget(close_button)

        self.add_widget(layout)

    def go_to_file_screen(self, instance):
        self.manager.current = 'second'

    def close_app(self, instance):
        App.get_running_app().stop()


class ScreenTwo(Screen):
    def __init__(self, **kwargs):
        super(ScreenTwo, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical')

        # Polje za unos podataka
        self.input_data = TextInput(hint_text='Unesite tekst za hash', size_hint=(1, 0.2))
        layout.add_widget(self.input_data)

        # Labela za svaki hash
        self.sha256_label = Label(text="SHA-256: ", size_hint=(1, 0.2))
        layout.add_widget(self.sha256_label)

        self.sha512_label = Label(text="SHA-512: ", size_hint=(1, 0.2))
        layout.add_widget(self.sha512_label)

        self.argon2_label = Label(text="Argon2: ", size_hint=(1, 0.2))
        layout.add_widget(self.argon2_label)

        self.bcrypt_label = Label(text="bcrypt: ", size_hint=(1, 0.2))
        layout.add_widget(self.bcrypt_label)

        self.blake2_label = Label(text="blake2: ", size_hint=(1, 0.2))
        layout.add_widget(self.blake2_label)

        self.salt_sha256_label = Label(text="salt_sha256: ", size_hint=(1, 0.2))
        layout.add_widget(self.salt_sha256_label)

        self.sha3256_label = Label(text="SHA3-256: ", size_hint=(1, 0.2))
        layout.add_widget(self.sha3256_label)

        self.sha3512_label = Label(text="SHA3-512: ", size_hint=(1, 0.2))
        layout.add_widget(self.sha3512_label)

        # Gumbi za generiranje svakog hash-a
        self.sha256_button = Button(text="Generiraj SHA-256", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.sha256_button.bind(on_press=self.generate_sha256)
        layout.add_widget(self.sha256_button)

        self.sha512_button = Button(text="Generiraj SHA-512", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.sha512_button.bind(on_press=self.generate_sha512)
        layout.add_widget(self.sha512_button)

        self.argon2_button = Button(text="Generiraj Argon2", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.argon2_button.bind(on_press=self.generate_argon2)
        layout.add_widget(self.argon2_button)

        self.bcrypt_button = Button(text="Generiraj bcrypt", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.bcrypt_button.bind(on_press=self.generate_bcrypt)
        layout.add_widget(self.bcrypt_button)

        self.blake2_button = Button(text="Generiraj blake2", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.blake2_button.bind(on_press=self.generate_blake2)
        layout.add_widget(self.blake2_button)

        self.salt_sha256_button = Button(text="Generiraj SALT + SHA-256", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.salt_sha256_button.bind(on_press=self.generate_salt_sha256)
        layout.add_widget(self.salt_sha256_button)

        self.sha3256_button = Button(text="Generiraj SHA3-256", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.sha3256_button.bind(on_press=self.generate_sha3256)
        layout.add_widget(self.sha3256_button)

        self.sha3512_button = Button(text="Generiraj SHA3-512", size_hint=(1, 0.2), background_color=(0, 1, 0, 1))
        self.sha3512_button.bind(on_press=self.generate_sha3512)
        layout.add_widget(self.sha3512_button)

        # Gumb za povratak na prvu stranicu
        back_button = Button(text="Natrag", background_color=(0, 0, 1, 1), size_hint=(1, 0.2))
        back_button.bind(on_press=self.go_back)
        layout.add_widget(back_button)

        self.add_widget(layout)

    # Generiranje pojedinih hash-ova
    def generate_sha256(self, instance):
        data = self.input_data.text
        sha256_hash = hashlib.sha256(data.encode()).hexdigest()
        self.sha256_label.text = f"SHA-256: {sha256_hash}"

    def generate_sha512(self, instance):
        data = self.input_data.text
        sha512_hash = hashlib.sha512(data.encode()).hexdigest()
        self.sha512_label.text = f"SHA-512: {sha512_hash}"

    def generate_argon2(self, instance):
        data = self.input_data.text
        ph = PasswordHasher()
        argon2_hash = ph.hash(data)
        self.argon2_label.text = f"ARGON2: {argon2_hash}"

    def generate_bcrypt(self, instance):
        data = self.input_data.text
        salt = bcrypt.gensalt()
        bcrypt_hash = bcrypt.hashpw(data.encode(), salt)
        self.bcrypt_label.text = f"BCRYPT: {bcrypt_hash.decode()}"

    def generate_blake2(self, instance):
        data = self.input_data.text
        blake2_hash = hashlib.blake2s(data.encode()).hexdigest()
        self.blake2_label.text = f"BLAKE2: {blake2_hash}"

    def generate_salt_sha256(self, instance):
        data = self.input_data.text
        salt = os.urandom(16)
        salted_hash = hashlib.sha256(salt + data.encode()).hexdigest()
        self.salt_sha256_label.text = f"SALT-SHA-256: {salt.hex()} - {salted_hash}"

    def generate_sha3256(self, instance):
        data = self.input_data.text
        sha3256_hash = hashlib.sha3_256(data.encode()).hexdigest()
        self.sha3256_label.text = f"SHA3-256: {sha3256_hash}"

    def generate_sha3512(self, instance):
        data = self.input_data.text
        sha3512_hash = hashlib.sha3_512(data.encode()).hexdigest()
        self.sha3512_label.text = f"SHA3-512: {sha3512_hash}"

    def go_back(self, instance):
        self.manager.current = 'first'


class KivyAplikacija(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(ScreenOne(name='first'))
        sm.add_widget(ScreenTwo(name='second'))
        return sm


if __name__ == '__main__':
    KivyAplikacija().run()

