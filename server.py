# serveur.py
import socket
import ssl
from threading import Thread
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
import datetime

# Liste pour stocker les connexions des clients
clients = {}  # username -> (conn, public_key)


def generate_self_signed_cert(certfile, keyfile):
    key = crypto_rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile-de-France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Mon Chat App"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Certificat valable pendant 1 an
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def broadcast_user_connected(username, public_key, exclude_conn=None):
    message = f"USER_CONNECTED:{username}:{public_key}".encode('utf-8')
    for user, (conn, _) in clients.items():
        if conn != exclude_conn:
            try:
                conn.sendall(message)
            except Exception as e:
                print(f"Erreur en envoyant USER_CONNECTED à {user}: {e}")

def broadcast_user_disconnected(username):
    message = f"USER_DISCONNECTED:{username}".encode('utf-8')
    for user, (conn, _) in clients.items():
        try:
            conn.sendall(message)
        except Exception as e:
            print(f"Erreur en envoyant USER_DISCONNECTED à {user}: {e}")

def handle_client(conn, addr):
    print(f"Connexion de {addr}")
    username = None
    public_key = None

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            message = data.decode('utf-8')

            if message.startswith("REGISTER:"):
                try:
                    _, username, pub_key_pem = message.split(":", 2)
                    if username in clients:
                        conn.sendall(f"ERROR:Username {username} already taken.".encode('utf-8'))
                        conn.close()
                        return
                    public_key = pub_key_pem
                    clients[username] = (conn, public_key)
                    print(f"Utilisateur enregistré: {username}")
                    # Envoyer à l'utilisateur la liste des utilisateurs déjà connectés
                    for user, (_, pub_key) in clients.items():
                        if user != username:
                            conn.sendall(f"USER_CONNECTED:{user}:{pub_key}".encode('utf-8'))
                    # Informer les autres utilisateurs de la nouvelle connexion
                    broadcast_user_connected(username, public_key, exclude_conn=conn)
                except ValueError:
                    conn.sendall("ERROR:Invalid REGISTER format.".encode('utf-8'))

            elif message.startswith("MESSAGE:"):
                try:
                    _, recipient, encrypted_msg = message.split(":", 2)
                    print(f"\n{message}\n")
                    if recipient in clients:
                        recipient_conn, _ = clients[recipient]
                        forward_message = f"MESSAGE:{username}:{encrypted_msg}".encode('utf-8')
                        print(f"\n{forward_message}\n")
                        recipient_conn.sendall(forward_message)
                        print(f"Message de {username} à {recipient} relayé.")
                    else:
                        conn.sendall(f"ERROR:User {recipient} not connected.".encode('utf-8'))
                except ValueError:
                    conn.sendall("ERROR:Invalid MESSAGE format.".encode('utf-8'))

            else:
                conn.sendall("ERROR:Unknown command.".encode('utf-8'))

    except Exception as e:
        print(f"Erreur avec {addr}: {e}")

    finally:
        if username:
            del clients[username]
            print(f"{username} s'est déconnecté.")
            broadcast_user_disconnected(username)
        conn.close()

def start_server():
    certfile = "cert.pem"
    keyfile = "key.pem"

    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        generate_self_signed_cert(certfile, keyfile)
        print("Certificat auto-signé généré.")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('localhost', 1060))
        sock.listen(5)
        print("Serveur en écoute sur le port 1060...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    Thread(target=handle_client, args=(conn, addr), daemon=True).start()
                except Exception as e:
                    print(f"Erreur d'acceptation de connexion: {e}")

if __name__ == "__main__":
    start_server()
