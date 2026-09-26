import sys
from pathlib import Path
from django.core.management.base import BaseCommand

from freedec.services import DocumentManagementService


class Command(BaseCommand):
    help = "Descifra un archivo .enc de Freedec utilizando su contraseña legítima y guarda el archivo original."

    def add_arguments(self, parser):
        parser.add_argument("encrypted_file", type=str, help="Ruta al archivo .enc que se desea descifrar.")
        parser.add_argument("--password", "-p", type=str, required=True, help="Contraseña de descifrado entregada al destinatario.")
        parser.add_argument("--output", "-o", type=str, required=False, help="Ruta de destino del archivo descifrado (opcional).")

    def handle(self, *args, **options):
        enc_path = Path(options["encrypted_file"])
        password = options["password"]
        output_arg = options.get("output")

        if not enc_path.exists():
            self.stdout.write(self.style.ERROR(f"Error: El archivo '{enc_path}' no existe."))
            sys.exit(1)

        self.stdout.write(self.style.NOTICE(f"Descifrando archivo '{enc_path}' con la contraseña facilitada..."))

        service = DocumentManagementService()
        with open(enc_path, "rb") as f:
            success, decrypted_bytes, suggested_filename, mimetype, message = (
                service.decrypt_document_with_password(
                    encrypted_file_obj=f,
                    password=password,
                )
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
