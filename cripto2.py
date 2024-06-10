import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import pandas as pd
import io

# Variables globales para almacenar las claves públicas y privadas
public_keys = {}
private_keys = {}

def load_keys_from_excel(file):
    global public_keys, private_keys
    st.write("Cargando claves desde el archivo Excel")
    try:
        df = pd.read_excel(file)
        for index, row in df.iterrows():
            n = int(row[1])
            e = int(row[2])
            d = int(row[3])
            p = int(row[4])
            q = int(row[5])
            dp = int(row[6])
            dq = int(row[7])
            qi = int(row[8])
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            private_key = rsa.RSAPrivateNumbers(
                p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi,
                public_numbers=rsa.RSAPublicNumbers(e, n)
            ).private_key()
            public_keys[row[0]] = public_key
            private_keys[row[0]] = private_key
    except Exception as e:
        st.error(f"Error al leer el archivo Excel: {e}")

def create_hash(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def sign_data(data: bytes, signer: str) -> bytes:
    global private_keys
    private_key = private_keys.get(signer)
    if private_key is None:
        st.error(f"No se encontró la clave privada para el firmante: {signer}")
        return None
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes, signer: str) -> bool:
    global public_keys
    public_key = public_keys.get(signer)
    if public_key is None:
        st.error(f"No se encontró la clave pública para el firmante: {signer}")
        return False
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        st.error(f"Error al verificar la firma: {e}")
        return False

def main():
    st.title("Generador y Verificador de Firmas Digitales")
    
    uploaded_excel = st.file_uploader("Sube el archivo Excel con las claves", type=["xlsx"])
    if uploaded_excel:
        st.write("Archivo Excel subido")
        load_keys_from_excel(uploaded_excel)

    menu = ["Generar Firma Digital", "Verificar Firma Digital"]
    choice = st.sidebar.selectbox("Menú", menu)

    if choice == "Generar Firma Digital":
        st.subheader("Generar Firma Digital")
        signer_info = st.text_input("Ingrese el nombre completo del firmante:")
        document = st.file_uploader("Sube el documento a firmar", type=["txt", "pdf", "docx"])

        if st.button("Generar Firma") and document and signer_info:
            st.write("Generando firma...")
            document_bytes = document.read()
            document_hash = create_hash(document_bytes + signer_info.encode('utf-8'))
            signature = sign_data(document_hash, signer_info)
            if signature:
                st.success("Firma generada con éxito.")
                st.download_button("Descargar Firma", data=signature, file_name=f"{document.name}.sign")

    elif choice == "Verificar Firma Digital":
        st.subheader("Verificar Firma Digital")
        signer_info = st.text_input("Ingrese el nombre completo del firmante:")
        document = st.file_uploader("Sube el documento original", type=["txt", "pdf", "docx"])
        signature_file = st.file_uploader("Sube el archivo de la firma (.sign)", type=["sign"])

        if st.button("Verificar Firma") and document and signer_info and signature_file:
            st.write("Verificando firma...")
            document_bytes = document.read()
            signature = signature_file.read()
            document_hash = create_hash(document_bytes + signer_info.encode('utf-8'))
            is_valid = verify_signature(document_hash, signature, signer_info)
            if is_valid:
                st.success("La firma es válida.")
            else:
                st.error("La firma no es válida.")

if __name__ == "__main__":
    main()
