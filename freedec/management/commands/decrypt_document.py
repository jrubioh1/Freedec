import hashlib
import sys
from pathlib import Path
from django.core.management.base import BaseCommand

from freedec.models import EncryptedDocument
from freedec.services import DocumentManagementService


class Command(BaseCommand):
    help = "Descifra un archivo .enc de Freedec utilizando un token, código OTP o credencial administrativa."

    def add_arguments(self, parser):
        parser.add_argument("encrypted_file", type=str, help="Ruta al archivo .enc que se desea descifrar.")
        parser.add_argument("--token", "-t", type=str, required=False, help="Token de enlace mágico recibido por correo.")
        parser.add_argument("--otp", type=str, required=False, help="Código OTP de 6 dígitos recibido por correo.")
        parser.add_argument("--email", "-e", type=str, required=False, help="Correo electrónico autorizado (requerido con --otp).")
        parser.add_argument("--admin", action="store_true", help="Descifrado administrativo preservado usando la clave de servidor (Audit Bypass).")
        parser.add_argument("--password", "-p", type=str, required=False, help="Alias de compatibilidad para token u OTP.")
        parser.add_argument("--output", "-o", type=str, required=False, help="Ruta de destino del archivo descifrado (opcional).")

    def handle(self, *args, **options):
        enc_path = Path(options["encrypted_file"])
        token = options.get("token")
        otp = options.get("otp")
        email = options.get("email")
        is_admin = options.get("admin")
        password = options.get("password")
        output_arg = options.get("output")

        if not enc_path.exists():
            self.stdout.write(self.style.ERROR(f"Error: El archivo '{enc_path}' no existe."))
            sys.exit(1)

        service = DocumentManagementService()

        if is_admin:
            self.stdout.write(self.style.NOTICE(f"Ejecutando descifrado administrativo preservado para '{enc_path}'..."))
            enc_bytes = enc_path.read_bytes()
            enc_hash = hashlib.sha256(enc_bytes).hexdigest()
            doc = EncryptedDocument.objects.filter(encrypted_file_hash=enc_hash).first()
            if not doc:
                # Intentar por nombre original
                doc = EncryptedDocument.objects.filter(original_filename__icontains=enc_path.stem).first()

            if not doc:
                self.stdout.write(self.style.ERROR("❌ No se encontró ningún documento registrado que coincida con este archivo cifrado."))
                sys.exit(1)

            success, decrypted_bytes, suggested_filename, mimetype, message = service.admin_decrypt_document(
                document=doc,
                admin_user="cli_admin",
            )
        else:
            # Compatibilidad si pasaron --password
            token_str = token or (password if password and len(password.strip()) > 6 else None)
            otp_code = otp or (password if password and len(password.strip()) == 6 else None)

            if not token_str and not otp_code:
                self.stdout.write(self.style.ERROR("Error: Debe especificar --token, --otp (con --email) o --admin."))
                sys.exit(1)

            self.stdout.write(self.style.NOTICE(f"Consumiendo y descifrando archivo '{enc_path}' (Burn-After-Read)..."))
            success, decrypted_bytes, suggested_filename, mimetype, message = service.consume_and_burn_document(
                token_str=token_str,
                otp_code=otp_code,
                email=email,
            )

        if not success:
            self.stdout.write(self.style.ERROR(f"❌ Fallo al descifrar: {message}"))
            sys.exit(1)

        if output_arg:
            out_path = Path(output_arg)
        else:
            out_path = enc_path.parent / suggested_filename

        out_path.write_bytes(decrypted_bytes)
        self.stdout.write(self.style.SUCCESS(f"\n✅ ¡Documento descifrado exitosamente!"))
        self.stdout.write(self.style.SUCCESS(f"   Archivo guardado en: {out_path.resolve()}"))
        self.stdout.write(f"   Tamaño: {len(decrypted_bytes):,} bytes | MIME: {mimetype}\n")
