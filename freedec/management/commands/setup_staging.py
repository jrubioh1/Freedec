from pathlib import Path
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand

User = get_user_model()

MINIMAL_VALID_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


class Command(BaseCommand):
    help = "Inicializa el entorno de Staging Sandbox de Freedec (migraciones, superusuario y archivos demo PDF/Office)."

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("=== 1. Ejecutando migraciones de base de datos ==="))
        try:
            call_command("makemigrations", "freedec", interactive=False)
        except Exception:
            pass
        call_command("migrate", interactive=False)

        self.stdout.write(self.style.MIGRATE_HEADING("=== 2. Configurando superusuario de prueba ==="))
        admin_username = "admin"
        admin_email = "admin@freedec.local"
        admin_pass = "admin123"

        if not User.objects.filter(username=admin_username).exists():
            User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_pass,
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"✓ Superusuario creado exitosamente: usuario='{admin_username}', contraseña='{admin_pass}'"
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(f"El usuario '{admin_username}' ya existe. No se modificó.")
            )

        self.stdout.write(self.style.MIGRATE_HEADING("=== 3. Creando archivo de demostración (PDF Válido) ==="))
        demo_file_path = Path("sample_document.pdf")
        demo_file_path.write_bytes(MINIMAL_VALID_PDF)
        self.stdout.write(self.style.SUCCESS(f"✓ Archivo PDF de prueba creado: {demo_file_path.resolve()}"))

        self.stdout.write(self.style.SUCCESS("\n========================================================"))
        self.stdout.write(self.style.SUCCESS("✓ ENTORNO DE STAGING SANDBOX LISTO PARA PROBAR"))
        self.stdout.write(self.style.SUCCESS("========================================================"))
        self.stdout.write("Para iniciar el servidor de pruebas:")
        self.stdout.write(self.style.WARNING("  poetry run python manage.py runserver 8000"))
        self.stdout.write("\nPara ejecutar la prueba de flujo automatizada (en otra terminal):")
        self.stdout.write(self.style.WARNING("  poetry run python scripts/demo_flow.py"))
        self.stdout.write("========================================================\n")
