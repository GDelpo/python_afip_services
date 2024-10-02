import datetime as dt
import email
import os
import re
from enum import Enum

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs7
import xmltodict
import zeep
from zeep.helpers import serialize_object

class TicketAutorizacion:
    def __init__(self, response_dict):
        self.token = self.set_token(response_dict)
        self.sign = self.set_sign(response_dict)
        self.expiration_time = self.set_expiration_time(response_dict)
        self.number_cuit = self.set_number_cuit(response_dict)

    def set_token(self, response_dict):
        return response_dict['loginTicketResponse']['credentials']['token']
    
    def set_sign(self, response_dict):
        return response_dict['loginTicketResponse']['credentials']['sign']
    
    def set_expiration_time(self, response_dict):
        expiration_str = response_dict['loginTicketResponse']['header']['expirationTime']
        return dt.datetime.fromisoformat(expiration_str)
    
    def is_valid(self):
        return dt.datetime.now(dt.timezone.utc).astimezone() < self.expiration_time
    
    def set_number_cuit(self, response_dict):
        cuit_number = None
        destination = response_dict['loginTicketResponse']['header']['destination']
        cuit_match = re.search(r'CUIT (\d+)', destination)
        if cuit_match:
            cuit_number = cuit_match.group(1)
        return cuit_number
            
    def __str__(self):
        return f"Token: {self.token}\nSign: {self.sign}\nExpiration Time: {self.expiration_time}\nCUIT: {self.number_cuit}"
    
class WSAAClient:
    """
    A client for authenticating with AFIP's WSAA (Web Services Authentication and Authorization).

    Attributes:
        service_name (str): The name of the AFIP service to access.
        private_key_path (str): The path to the private key file.
        certificate_path (str): The path to the certificate file.
        passphrase (str): The passphrase for the private key, if any.
        is_production (bool): Flag to determine if the environment is production or testing.
    """

    def __init__(self, service_name, certificate_path, private_key_path, is_production=True, passphrase=None):
        self.service_name = service_name
        self.certificate = self.set_certificate(certificate_path)
        self.private_key = self.set_private_key(private_key_path, passphrase)        
        self.is_production = is_production
        self.authorization = None
        
    def set_private_key(self, private_key_path, passphrase):
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")
        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=passphrase.encode() if passphrase else None,
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            raise RuntimeError(f"Error when loading private key: {str(e)}")
    
    def set_certificate(self, certificate_path):
        if not os.path.exists(certificate_path):
            raise FileNotFoundError(f"Certificate file not found: {certificate_path}")
        try:
            with open(certificate_path, "rb") as cert_file:
                certificate = x509.load_pem_x509_certificate(
                    cert_file.read(),
                    backend=default_backend()
                )
            return certificate
        except Exception as e:
            raise RuntimeError(f"Error when loading certificate: {str(e)}")
    
    def create_tra_xml(self):
        """Generate a Ticket Request XML (TRA) for the specified AFIP service."""
        try:
            start_time = dt.datetime.now() - dt.timedelta(minutes=10)
            end_time = start_time + dt.timedelta(minutes=20)
            tra_data = {
                'loginTicketRequest': {
                    '@version': '1.0',
                    'header': {
                        'uniqueId': start_time.strftime("%y%m%d"),
                        'generationTime': start_time.strftime("%Y-%m-%dT%H:%M:%S"),
                        'expirationTime': end_time.strftime("%Y-%m-%dT%H:%M:%S"),
                    },
                    'service': self.service_name
                }
            }

            return xmltodict.unparse(tra_data, pretty=True)
        except Exception as e:
            raise RuntimeError(f"Error when creating TRA XML: {str(e)}")

    def sign_tra(self, tra_xml):
        """Sign the TRA XML using the private key and certificate to create a CMS.

        Args:
            tra_xml (str): The TRA XML string to be signed.

        Returns:
            str: The signed CMS in base64 encoding.

        Raises:
            RuntimeError: If the CMS part is not found.
        """
        try:
            cms = pkcs7.PKCS7SignatureBuilder().set_data(
                tra_xml.encode('utf-8')
            ).add_signer(
                self.certificate, self.private_key, hashes.SHA256()
            ).sign(
                serialization.Encoding.SMIME, [pkcs7.PKCS7Options.Binary]
            )
            msg = email.message_from_string(cms.decode("utf8"))
            for part in msg.walk():
                if part.get_filename() and part.get_filename().startswith("smime.p7"):
                    return part.get_payload(decode=False)
            raise RuntimeError("CMS part not found")
        except Exception as e:
            raise RuntimeError(f"Error when signing TRA: {str(e)}")
    
    def request_afip_authorization(self, cms_base64):
        """Send the signed CMS to AFIP to get the authorization.

        Args:
            cms_base64 (str): The signed CMS in base64 encoding.

        Returns:
            dict: The authorization response from AFIP.

        Raises:
            Exception: If there is an error when calling the AFIP service.
        """
        wsdl_url = self.get_wsdl_url()
        client = zeep.Client(wsdl=wsdl_url)
        try:
            response = client.service.loginCms(in0=cms_base64)
            return xmltodict.parse(response)
        except Exception as e:
            raise RuntimeError(f"Error when calling AFIP service: {str(e)}")

    def get_wsdl_url(self):
        """Get the appropriate WSDL URL based on the production flag.

        Returns:
            str: The WSDL URL for the AFIP service.
        """
        if self.is_production:
            return "https://wsaa.afip.gov.ar/ws/services/LoginCms?WSDL"
        else:
            return "https://wsaahomo.afip.gov.ar/ws/services/LoginCms?WSDL"
        
    def authenticate(self):
        """Authenticate with AFIP by generating and signing the TRA, then sending it to AFIP."""
        tra_xml = self.create_tra_xml()
        signed_cms = self.sign_tra(tra_xml)
        self.authorization = self.request_afip_authorization(signed_cms)
    
    def get_authorization_ticket(self):
        """Get the token from the authorization response."""
        if self.authorization is None:
            raise ValueError("Authorization is not available.")
        return TicketAutorizacion(self.authorization)

class WSNService(Enum):
    WS_SR_CONSTANCIA_INSCRIPCION = "ws_sr_constancia_inscripcion"
    WS_SR_PADRON_A13 = "ws_sr_padron_a13"

    def get_urls(self, is_production):
        """
        Returns the URLs for a specific service based on the environment.

        Args:
            is_production (bool): Indicates whether the environment is production or testing.

        Returns:
            dict: A dictionary containing the service URL and WSDL URL for the specified environment.
        """
        urls = {
            "ws_sr_constancia_inscripcion": {
                "testing": {
                    "service_url": "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5",
                    "wsdl_url": "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL"
                },
                "production": {
                    "service_url": "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5",
                    "wsdl_url": "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL"
                }
            },
            "ws_sr_padron_a13": {
                "testing": {
                    "service_url": "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA13",
                    "wsdl_url": "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA13?WSDL"
                },
                "production": {
                    "service_url": "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA13",
                    "wsdl_url": "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA13?WSDL"
                }
            }
        }
        environment = "production" if is_production else "testing"
        return urls[self.value][environment]
    
    def get_method_name(self):
        """
        Returns the method name based on the value of `self.value`.

        Returns:
            str: The method name corresponding to the value.

        Raises:
            KeyError: If the value is not found in the `method_names` dictionary.
        """
        method_names = {
            "ws_sr_constancia_inscripcion": "getPersonaList_v2",
            "ws_sr_padron_a13": "getPersona"
        }
        return method_names[self.value]

class WSN:
    def __init__(self, service: WSNService, cert_path, key_path, is_production=True, passphrase=None):
        self.service = service
        self.wsaa_client = WSAAClient(service.value, cert_path, key_path, is_production, passphrase)
        self.authorization_ticket = None

    def obtain_authorization_ticket(self):
        """
        Obtains the authorization ticket for the AFIP web service.
        
        This method authenticates the client using the `wsaa_client` and retrieves
        the authorization ticket required for accessing the AFIP web service.
        """
        self.wsaa_client.authenticate()
        self.authorization_ticket = self.wsaa_client.get_authorization_ticket()
        
    def request_afip_dummy(self):
        """
        Sends a request to the AFIP service to check if it is operational.

        Returns:
            bool: True if the AFIP service is operational, False otherwise.

        Raises:
            RuntimeError: If there is an error when calling the AFIP service.
        """
        wsdl_url = self.get_wsn_url()
        client = zeep.Client(wsdl=wsdl_url)

        try:
            response = client.service.dummy()
            is_operational = response['appserver'] == 'OK' and response['authserver'] == 'OK' and response['dbserver'] == 'OK'
            return is_operational
        except Exception as e:
            raise RuntimeError(f"Error when calling AFIP service: {str(e)}")

    def request_persona_list(self, persona_ids):
        """
        Requests a list of personas from the AFIP service.

        Args:
            persona_ids (list): A list of persona IDs to retrieve.

        Returns:
            list: A list of dictionaries, where each dictionary contains the persona ID as the key and the serialized persona object as the value.

        Raises:
            RuntimeError: If an error occurs when calling the AFIP service.
        """
        # Check if the authorization ticket is valid or obtain a new one
        if not self.authorization_ticket or not self.authorization_ticket.is_valid():
            self.obtain_authorization_ticket()

        wsdl_url = self.get_wsn_url()
        client = zeep.Client(wsdl=wsdl_url)
        method_name = self.service.get_method_name()

        personas_list = []
        try:
            if method_name == "getPersonaList_v2":
                persona_ids_long = [int(persona_id) for persona_id in persona_ids]
                response = client.service.getPersonaList_v2(
                    token=self.authorization_ticket.token,
                    sign=self.authorization_ticket.sign,
                    cuitRepresentada=int(self.authorization_ticket.number_cuit),
                    idPersona=persona_ids_long
                )
                # Asumimos que 'response['persona']' es una lista de personas en el mismo orden que 'persona_ids'
                for i, persona in enumerate(response['persona']):
                    serialized_persona = serialize_object(persona)
                    personas_list.append({persona_ids[i]: serialized_persona})
            else:  # method_name == "getPersona"
                for i, persona_id in enumerate(persona_ids):
                    try:
                        single_response = client.service.getPersona(
                            token=self.authorization_ticket.token,
                            sign=self.authorization_ticket.sign,
                            cuitRepresentada=int(self.authorization_ticket.number_cuit),
                            idPersona=int(persona_id)
                        )
                        serialized_persona = serialize_object(single_response['persona'])
                        personas_list.append({persona_id: serialized_persona})
                    except Exception as e:
                        personas_list.append({persona_id: e})
        except Exception as e:
            raise RuntimeError(f"Error when calling AFIP service: {str(e)}")
        finally:
            return personas_list

    def get_wsn_url(self):
        """
        Returns the WSN URL for the current service.

        :return: The WSN URL.
        """
        urls = self.service.get_urls(self.wsaa_client.is_production)
        return urls["wsdl_url"]    