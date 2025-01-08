# client.py
import socket
import ssl
import rsa
import threading

DATABASE = 'chat.db'

def generate_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key


def listen_server(conn, private_key, known_users):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("Déconnecté du serveur.")
                break
            message = data.decode('utf-8')
            if message.startswith("USER_CONNECTED:"):
                _, username, pub_key_pem = message.split(":", 2)
                known_users[username] = rsa.PublicKey.load_pkcs1(pub_key_pem.encode('utf-8'))
                print(f"\n{username} s'est connecté.")
            elif message.startswith("USER_DISCONNECTED:"):
                _, username = message.split(":", 1)
                if username in known_users:
                    del known_users[username]
                print(f"\n{username} s'est déconnecté.")
            elif message.startswith("MESSAGE:"):
                try:
                    _, sender, encrypted_msg = message.split(":", 2)
                    encrypted_bytes = bytes.fromhex(encrypted_msg)
                    decrypted_message = rsa.decrypt(encrypted_bytes, private_key).decode('utf-8')
                    print(f"\nMessage de {sender}: {decrypted_message}")
                except Exception as e:
                    print(f"\nErreur de déchiffrement du message de {sender}: {e}")
            elif message.startswith("ERROR:"):
                _, error_msg = message.split(":", 1)
                print(f"\nErreur du serveur: {error_msg}")
            else:
                print(f"\nMessage inconnu: {message}")
        except Exception as e:
            print(f"\nErreur de connexion: {e}")
            break

def start_client():
    username = input("Entrez votre nom d'utilisateur: ")
    public_key, private_key = generate_keys()
    print("Clés générées et stockées.")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False  # Pour le développement local
    context.verify_mode = ssl.CERT_NONE  # Pour le développement local

    with socket.create_connection(('localhost', 1060)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:
            print("Connecté au serveur.")
            # Envoyer le message d'enregistrement
            ssock.sendall(f"REGISTER:{username}:{public_key.save_pkcs1().decode('utf-8')}".encode('utf-8'))

            known_users = {}  # username -> public_key

            # Démarrer un thread pour écouter les messages du serveur
            listener_thread = threading.Thread(target=listen_server, args=(ssock, private_key, known_users), daemon=True)
            listener_thread.start()

            while True:
                try:
                    print("\nOptions:")
                    print("1. Envoyer un message")
                    print("2. Afficher les utilisateurs connectés")
                    print("3. Quitter")
                    choice = input("Choisissez une option (1/2/3): ")

                    if choice == "1":
                        recipient = input("Entrez le nom d'utilisateur du destinataire: ")
                        if recipient == username:
                            print("Vous ne pouvez pas vous envoyer un message à vous-même.")
                            continue
                        if recipient not in known_users:
                            print("Utilisateur inconnu ou non connecté.")
                            continue
                        message = input("Entrez votre message: ")
                        recipient_pub_key = known_users[recipient]
                        encrypted_message = rsa.encrypt(message.encode('utf-8'), recipient_pub_key)
                        # Envoyer le message sous forme hexadécimale pour éviter des problèmes d'encodage
                        encrypted_hex = encrypted_message.hex()
                        ssock.sendall(f"MESSAGE:{recipient}:{encrypted_hex}".encode('utf-8'))
                        print("Message envoyé.")

                    elif choice == "2":
                        if known_users:
                            print("Utilisateurs connectés:")
                            for user in known_users:
                                print(f"- {user}")
                        else:
                            print("Aucun utilisateur connecté.")
                    elif choice == "3":
                        print("Déconnexion...")
                        break
                    else:
                        print("Option invalide.")
                except Exception as e:
                    print(f"Erreur: {e}")
                    break

if __name__ == "__main__":
    start_client()
