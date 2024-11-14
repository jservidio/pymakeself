from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# tar --transform s/pymakeself/pymakeself-0.4.1/ --exclude-vcs -czvf pymakeself-0.4.1.tar.gz pymakeself

def GetSignature(private_key_file, data):
    with open(private_key_file, "rb") as priv_key:
        private_key = serialization.load_ssh_private_key(
            priv_key.read(),
            None
        )

    signature = private_key.sign(
        data,
        padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
    )

    return signature


def VerifySignature(signature, data, public_key_file):
    with open(public_key_file, "rb") as pub_key:
        public_key = serialization.load_ssh_public_key(
            pub_key.read(),
        )

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    except InvalidSignature:
        raise RuntimeError("Invalid key signature")
