import os
from pprint import pprint

from models import WSN, WSNService


if __name__ == "__main__":
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cert_dir = os.path.join(base_dir, 'certificates')
    certs_dir = os.path.join(cert_dir, 'certs')
    private_dir = os.path.join(cert_dir, 'private')
    tickets_dir = os.path.join(cert_dir, 'tickets')
    os.makedirs(tickets_dir, exist_ok=True)

    cert_file_path = os.path.join(certs_dir, 'NOMBRE ARCHIVO DE CRT')
    key_file_path = os.path.join(private_dir, 'NOMBRE ARCHIVO DE CRT')

    # Example CUITs LIMITE MAXIMO 250
    cuits = ['NRO CUIT']
  
    # Initialize WSN for 'ws_sr_constancia_inscripcion' service
    wsn = WSN(WSNService.WS_SR_CONSTANCIA_INSCRIPCION, cert_file_path, key_file_path)
    #wsn = WSN(WSNService.WS_SR_PADRON_A13, cert_file_path, key_file_path)
    
    # Obtain Authorization Ticket
    wsn.obtain_authorization_ticket()

    # Send dummy request to check service status
    service_status = wsn.request_afip_dummy()
    print(f"Service status: {'OK' if service_status else 'Not OK'}")

    # Example: Request persona list
    persona_list_response = wsn.request_persona_list(cuits)
    pprint(persona_list_response)   