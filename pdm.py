"""
Personal Data Manager (PDM)
A secure password management application built with NiceGUI that allows users to store and manage their credentials.
Features:
- User authentication (login/signup)
- Secure password storage using encryption
- Add, view, edit, and delete credential entries
- Dark mode support
"""

from nicegui import ui, app
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Application configuration
NATIVE = False  # Set to True for native window mode, False for web mode
WINDOW_SIZE = (800, 800)
USER_DATA_DIR = "user_data"
SALT = b'fixed_salt_use_env_var_in_prod'  # In production, use environment variable for salt

# Create directory for storing user data if it doesn't exist
os.makedirs(USER_DATA_DIR, exist_ok=True)

def derive_key(password: str) -> bytes:
    # get key from password, just using pbkdf2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,  # kinda slow for security
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: str, key: bytes) -> str:
    # encrypt stuff with fernet
    return Fernet(key).encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    # decrypt stuff
    return Fernet(key).decrypt(encrypted_data.encode()).decode()

def get_user_file(username: str) -> str:
    # just get the file path for user
    return os.path.join(USER_DATA_DIR, f"{username}_data.json")

@ui.page("/")
async def index(client):
    # main page, does login and password stuff
    await ui.context.client.connected()

    @client.on_disconnect
    def shutdown():
        # quit app if user leaves
        app.shutdown()

    # dark mode stuff
    dark_mode = ui.dark_mode(False)
    def toggle_dark_mode():
        # switch dark/light
        dark_mode.value = not dark_mode.value
        dark_mode_btn.icon = "light_mode" if dark_mode.value else "dark_mode"
        dark_mode_btn.text = "Light Mode" if dark_mode.value else "Dark Mode"

    # button for dark mode
    with ui.page_sticky(position="bottom-right", x_offset=10, y_offset=10):
        dark_mode_btn = ui.button("Dark Mode", icon="dark_mode", on_click=toggle_dark_mode)

    # containers for login and main app
    login_container = ui.column().classes("w-full h-full")
    password_manager_container = ui.column().classes("w-full h-full")

    password_manager_container.visible = False

    # login ui
    with login_container:
        with ui.card() as login_card:
            login_card.classes("w-96 mx-auto p-4").style("max-height:90vh")
            # tabs for login/signup
            with ui.tabs().classes("w-full") as tabs:
                login_tab = ui.tab("Log In")
                signup_tab = ui.tab("Sign Up")
            with ui.tab_panels(tabs, value=login_tab).classes("w-full"):
                # login tab
                with ui.tab_panel(login_tab):
                    login_username = ui.input("Username")
                    login_password = ui.input("Password", password=True)

                    def handle_login():
                        # try to log in
                        try:
                            username_val = login_username.value.strip()
                            password_val = login_password.value
                            if not username_val or not password_val:
                                ui.notify("Please fill in all fields", type="negative")
                                return

                            user_file = get_user_file(username_val)
                            if not os.path.exists(user_file):
                                ui.notify("Account does not exist", type="negative")
                                return

                            # check password
                            with open(user_file, 'r') as f:
                                data = json.load(f)
                            stored_key = data.get("key", "")
                            entered_key = derive_key(password_val).decode()
                            if stored_key != entered_key:
                                ui.notify("Invalid password", type="negative")
                                return
                            # ok, show main app
                            login_container.visible = False
                            password_manager_container.visible = True
                            show_password_manager(username_val, derive_key(password_val))
                            ui.notify("Login successful!", type="positive")
                        except Exception as e:
                            ui.notify(f"Error during login: {str(e)}", type="negative")
                            return

                    ui.button("Log In", on_click=handle_login).classes("w-full mt-4")

                # signup tab
                with ui.tab_panel(signup_tab):
                    signup_username = ui.input("Username")
                    signup_password = ui.input("Password", password=True)

                    def handle_signup():
                        # make new user
                        try:
                            username_val = signup_username.value.strip()
                            password_val = signup_password.value
                            if not username_val or not password_val:
                                ui.notify("Please fill in all fields", type="negative")
                                return

                            user_file = get_user_file(username_val)
                            if os.path.exists(user_file):
                                ui.notify("Username already exists", type="negative")
                                return

                            # save user
                            key = derive_key(password_val)
                            user_data = {
                                "key": key.decode(),
                                "services": []
                            }
                            with open(user_file, 'w') as f:
                                json.dump(user_data, f)
                            ui.notify("Account created successfully!", type="positive")
                            signup_username.set_value(None)
                            signup_password.set_value(None)
                            tabs.value = login_tab
                        except Exception as e:
                            ui.notify(f"Error during signup: {str(e)}", type="negative")

                    ui.button("Sign Up", on_click=handle_signup).classes("w-full mt-4")

    # password manager ui
    def show_password_manager(username: str, key: bytes):
        # show the main app for passwords
        with password_manager_container:
            with ui.column().classes("w-full p-4 gap-4"):
                # header
                with ui.row().classes("w-full justify-between items-center"):
                    ui.label(f"Welcome, {username}!").classes("text-2xl font-bold")
                    with ui.row().classes("gap-2"):
                        add_button = ui.button("Add New Entry", icon="add", on_click=lambda: show_entry_dialog())
                        add_button.classes("bg-primary text-white")
                        logout_button = ui.button("Logout", icon="logout", on_click=lambda: handle_logout())
                        logout_button.classes("bg-red text-white")

                vault_container = ui.column().classes("w-full gap-4")

                def handle_logout():
                    # log out
                    password_manager_container.clear()
                    password_manager_container.visible = False
                    login_container.visible = True
                    login_username.set_value(None)
                    login_password.set_value(None)
                    tabs.value = login_tab
                    ui.notify("Logged out successfully", type="positive")

                def refresh_vault():
                    # update the list of passwords
                    try:
                        vault_container.clear()
                        with open(get_user_file(username), 'r') as f:
                            data = json.load(f)

                        if not data["services"]:
                            # nothing here
                            with vault_container:
                                with ui.card().classes("w-full text-center p-8"):
                                    ui.icon("folder_off", size="xl").classes("text-gray-400")
                                    ui.label("No entries found").classes("text-lg mt-4")
                                    ui.label("Click 'Add New Entry' to store your first credential")
                        else:
                            # show all entries
                            for entry in data["services"]:
                                with vault_container:
                                    with ui.card().classes("w-full p-4 hover:bg-gray-100"):
                                        with ui.row().classes("w-full items-center justify-between"):
                                            ui.icon("public").classes("text-gray-600")
                                            ui.label(entry["website"]).classes("flex-grow mx-4")

                                            def show_view_dialog(e=entry):
                                                # see entry details
                                                dialog = ui.dialog()
                                                with dialog, ui.card().classes("w-full p-4"):
                                                    ui.label(f"Website: {e['website']}").classes("font-bold text-xl")
                                                    with ui.column().classes("w-full gap-2"):
                                                        ui.input("User ID", value=decrypt_data(e["user_id"], key)).props("readonly")
                                                        pw_input = ui.input("Password", value=decrypt_data(e["password"], key)).props("readonly type=password")
                                                        is_password_visible = False

                                                        def toggle_pw():
                                                            # show/hide password
                                                            nonlocal is_password_visible
                                                            is_password_visible = not is_password_visible
                                                            if is_password_visible:
                                                                pw_input.props("type=text")
                                                                eye_btn.icon = "visibility_off"
                                                            else:
                                                                pw_input.props("type=password")
                                                                eye_btn.icon = "visibility"

                                                        eye_btn = ui.button(icon="visibility", on_click=toggle_pw)
                                                    ui.button("Close", on_click=dialog.close)
                                                dialog.open()

                                            def show_edit_dialog(e=entry):
                                                # edit entry
                                                dialog = ui.dialog()
                                                with dialog, ui.card().classes("w-full p-4"):
                                                    ui.label("Edit Entry").classes("text-xl font-bold")
                                                    with ui.column().classes("w-full gap-4"):
                                                        website_edit = ui.input("Website Name", value=e["website"]).classes("w-full")
                                                        user_id_edit = ui.input("User ID / Email", value=decrypt_data(e["user_id"], key)).classes("w-full")
                                                        password_edit = ui.input("Password", value=decrypt_data(e["password"], key)).classes("w-full")

                                                        def save_edit():
                                                            # save changes
                                                            try:
                                                                if not website_edit.value or not user_id_edit.value or not password_edit.value:
                                                                    ui.notify("All fields are required", type="negative")
                                                                    return

                                                                user_file = get_user_file(username)
                                                                with open(user_file, 'r') as f:
                                                                    data = json.load(f)
                                                                for i, entry in enumerate(data["services"]):
                                                                    if entry == e:
                                                                        data["services"][i] = {
                                                                            "website": website_edit.value,
                                                                            "user_id": encrypt_data(user_id_edit.value, key),
                                                                            "password": encrypt_data(password_edit.value, key)
                                                                        }
                                                                        break
                                                                with open(user_file, 'w') as f:
                                                                    json.dump(data, f)
                                                                dialog.close()
                                                                refresh_vault()
                                                                ui.notify("Entry updated successfully", type="positive")
                                                            except Exception as ex:
                                                                ui.notify(f"Error updating entry: {str(ex)}", type="negative")

                                                        with ui.row().classes("w-full justify-end gap-2"):
                                                            ui.button("Cancel", on_click=dialog.close).props("flat")
                                                            ui.button("Save", on_click=save_edit).props("color=primary")
                                                dialog.open()

                                            def delete_entry(e=entry):
                                                # delete entry
                                                try:
                                                    user_file = get_user_file(username)
                                                    with open(user_file, 'r+') as f:
                                                        data = json.load(f)
                                                        data["services"] = [x for x in data["services"] if x != e]
                                                        f.seek(0)
                                                        json.dump(data, f)
                                                        f.truncate()
                                                    refresh_vault()
                                                    ui.notify("Entry deleted", type="warning")
                                                except Exception as e:
                                                    ui.notify(f"Error deleting entry: {str(e)}", type="negative")

                                            # buttons for entry
                                            with ui.row().classes("gap-2"):
                                                ui.button(icon="visibility", on_click=show_view_dialog).tooltip("View")
                                                ui.button(icon="edit", on_click=show_edit_dialog).tooltip("Edit")
                                                ui.button(icon="delete", color="red", on_click=delete_entry).tooltip("Delete")
                    except Exception as e:
                        ui.notify(f"Error loading vault: {str(e)}", type="negative")

                def show_entry_dialog():
                    # add new entry
                    dialog = ui.dialog()
                    with dialog, ui.card().classes("w-full p-4"):
                        with ui.column().classes("w-full gap-4"):
                            ui.label("Add New Entry").classes("text-xl font-bold")
                            website = ui.input("Website Name").classes("w-full")
                            user_id = ui.input("User ID / Email").classes("w-full")
                            password = ui.input("Password", password=True).classes("w-full")

                            def save_entry():
                                # save new entry
                                try:
                                    if not website.value or not user_id.value or not password.value:
                                        ui.notify("All fields are required", type="negative")
                                        return

                                    new_entry = {
                                        "website": website.value,
                                        "user_id": encrypt_data(user_id.value, key),
                                        "password": encrypt_data(password.value, key)
                                    }
                                    user_file = get_user_file(username)
                                    try:
                                        with open(user_file, 'r') as f:
                                            data = json.load(f)
                                    except FileNotFoundError:
                                        data = {"key": key.decode(), "services": []}
                                    data["services"].append(new_entry)
                                    with open(user_file, 'w') as f:
                                        json.dump(data, f)
                                    dialog.close()
                                    refresh_vault()
                                    ui.notify("Entry added successfully", type="positive")
                                    website.set_value("")
                                    user_id.set_value("")
                                    password.set_value("")
                                except Exception as e:
                                    ui.notify(f"Error saving entry: {str(e)}", type="negative")

                            with ui.row().classes("w-full justify-end gap-2"):
                                ui.button("Cancel", on_click=dialog.close).props("flat")
                                ui.button("Save", on_click=save_entry).props("color=primary")
                    dialog.open()

                refresh_vault()

# run the app
if NATIVE:
    ui.run(native=True, window_size=WINDOW_SIZE, title="Personal Data Manager")
else:
    ui.run(port=8000, title="Personal Data Manager")
