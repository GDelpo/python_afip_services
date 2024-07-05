# AFIP Web Services Client
Este módulo de Python facilita la autenticación y comunicación con los servicios web de la AFIP (Administración Federal de Ingresos Públicos), permitiendo obtener información y realizar operaciones mediante el WSAA (Web Services Authentication and Authorization) y diferentes WSN (Web Services Negocios).

Se proveen clases y métodos para gestionar la autenticación con el WSAA y la interacción con los servicios WSN. Además, se incluyen ejemplos de uso para solicitar información de personas y verificar el estado de los servicios de AFIP. 

Esto es el modelado, se puede aplicar a proyectos de Python que requieran interactuar con los servicios web de AFIP.

## Requisitos
Este proyecto requiere Python 3 en adelante. Se recomienda utilizar un entorno virtual para manejar las dependencias de forma aislada. Para configurar un entorno virtual y instalar las dependencias, sigue estos pasos:

```bash
python -m venv env 
source env/bin/activate  # En Windows usa env\Scripts\activate
pip install -r requirements.txt
```

## Clases y Métodos Principales
- WSAAClient: Gestiona la autenticación con el WSAA.
    create_tra_xml(): Crea un XML de solicitud de Ticket de Requerimiento de Acceso (TRA).
    sign_tra(): Firma el TRA con la clave privada y el certificado.
    request_afip_authorization(): Envía el TRA firmado a AFIP y recibe un ticket de autorización.
- WSN: Maneja las interacciones con un servicio específico de WSN.
    obtain_authorization_ticket(): Obtiene el ticket de autorización necesario para interactuar con el servicio WSN.
    request_afip_dummy(): Verifica si el servicio de AFIP está operativo.
    request_persona_list(): Solicita información de una lista de personas.
- WSNService(Enum): Enumeración de los servicios WSN disponibles. Acá se encuentran todas las posibles opciones de servicios a los que se puede acceder. Por ahora tenemos 2 servicios configurados: `ws_sr_constancia_inscripcion` y `ws_sr_padron_a13`.

## Ejemplos de Uso

```python
base_dir = os.path.dirname(os.path.abspath(__file__))
cert_dir = os.path.join(base_dir, 'certificates')
certs_dir = os.path.join(cert_dir, 'certs')
private_dir = os.path.join(cert_dir, 'private')
tickets_dir = os.path.join(cert_dir, 'tickets')
os.makedirs(tickets_dir, exist_ok=True)

cert_file_path = os.path.join(certs_dir, nombre_archivo_certificado)
key_file_path = os.path.join(private_dir, nombre_archivo_clave)

# Example CUITs
cuits = ['cuit1', 'cuit2', 'cuit3']

# Initialize WSN for 'ws_sr_constancia_inscripcion' service
wsn = WSN(WSNService.WS_SR_CONSTANCIA_INSCRIPCION, cert_file_path, key_file_path)

# Obtain Authorization Ticket
wsn.obtain_authorization_ticket()

# Send dummy request to check service status
service_status = wsn.request_afip_dummy()
print(f"Service status: {'OK' if service_status else 'Not OK'}")

# Example: Request persona list
persona_list_response = wsn.request_persona_list(cuits)
print(f"Persona list response: {persona_list_response}")
```
IMPORTANTE: Para poder utilizar este módulo, es necesario contar con un certificado y clave privada válidos, así como también con los archivos de configuración necesarios. Para más información, consultar la documentación oficial de AFIP.

