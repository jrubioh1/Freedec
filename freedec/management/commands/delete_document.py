import sys
from django.core.management.base import BaseCommand
from django.db.models import Q

from freedec.models import EncryptedDocument


class Command(BaseCommand):
    help = "Permite listar o eliminar documentos cifrados de la base de datos y de disco."

    def add_arguments(self, parser):
        parser.add_argument(
            "target",
            nargs="?",
            type=str,
            help="Nombre del archivo o hash SHA-256 del documento a eliminar.",
        )
        parser.add_argument(
            "--list",
            "-l",
            action="store_true",
            help="Lista todos los documentos cifrados registrados con sus detalles.",
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help="Elimina TODOS los documentos registrados (y sus archivos físicos asociados).",
        )

    def handle(self, *args, **options):
        if options["list"]:
            docs = EncryptedDocument.objects.all().order_by("-created_at")
            if not docs.exists():
                self.stdout.write(self.style.WARNING("No hay documentos cifrados registrados en el sistema."))
                return

            self.stdout.write(self.style.NOTICE(f"\n{'ID':<5} {'NOMBRE ARCHIVO':<30} {'ACCESOS':<9} {'ÚLTIMO ACCESO':<20} {'HASH (SHA-256)'}"))
            self.stdout.write("-" * 90)
            for d in docs:
                last_acc = d.last_accessed_at.strftime("%Y-%m-%d %H:%M") if d.last_accessed_at else "Nunca"
                self.stdout.write(
                    f"{d.id:<5} {d.original_filename[:28]:<30} {d.access_count:<9} {last_acc:<20} {d.file_hash[:16]}..."
                )
            self.stdout.write(self.style.SUCCESS(f"\nTotal: {docs.count()} documento(s) registrado(s).\n"))
            return

        if options["all"]:
            count = EncryptedDocument.objects.count()
            if count == 0:
                self.stdout.write(self.style.WARNING("No hay documentos para eliminar."))
                return
            # Se eliminan individualmente para disparar la señal post_delete que borra los archivos físicos
            for doc in EncryptedDocument.objects.all():
                doc.delete()
            self.stdout.write(self.style.SUCCESS(f"✅ Se han eliminado los {count} documentos y sus archivos físicos asociados."))
            return

        target = options.get("target")
        if not target:
            self.stdout.write(self.style.ERROR("Error: Debe especificar el nombre del archivo o hash, o usar --list."))
            sys.exit(1)

        # Buscar por coincidencia en nombre o hash
        docs = EncryptedDocument.objects.filter(
            Q(original_filename__icontains=target) | Q(file_hash__icontains=target)
        )

        if not docs.exists():
            self.stdout.write(self.style.ERROR(f"❌ No se encontró ningún documento que coincida con '{target}'."))
            sys.exit(1)

        for doc in docs:
            name = doc.original_filename
            h = doc.file_hash[:12]
            doc.delete()
            self.stdout.write(self.style.SUCCESS(f"✅ Documento '{name}' (hash {h}...) y su archivo físico eliminados."))
