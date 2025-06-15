import json
import boto3
import hashlib
import pyjwt
import os
from datetime import datetime, timedelta, timezone

# Cliente DynamoDB
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']
jwt_secret = os.environ['JWT_SECRET']
table = dynamodb.Table(table_name)

def lambda_response(status_code, body):
    """Función helper para respuestas consistentes"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
        },
        'body': json.dumps(body, default=str)
    }

def hash_password(password):
    """Función para hashear contraseñas"""
    return hashlib.sha256(password.encode()).hexdigest()

def crear_usuario(event, context):
    """Función para crear un nuevo usuario"""
    try:
        body = event['body']
        if isinstance(body, str):
            body = json.loads(body)
        
        required_fields = ['tenant_id', 'nombre', 'email', 'password']
        for field in required_fields:
            if field not in body or not body[field]:
                return lambda_response(400, {
                    'error': f'Campo requerido: {field}'
                })
        
        tenant_id = body['tenant_id']
        nombre = body['nombre']
        email = body['email']
        password = body['password']
        telefono = body.get('telefono', '')
        
        # Verificar si el usuario ya existe
        try:
            response = table.get_item(
                Key={
                    'tenant_id': tenant_id,
                    'email': email
                }
            )
            if 'Item' in response:
                return lambda_response(400, {
                    'error': 'Usuario ya existe con este email'
                })
        except Exception as e:
            print(f"Error verificando usuario existente: {str(e)}")
        
        usuario_item = {
            'tenant_id': tenant_id,
            'email': email,
            'nombre': nombre,
            'password': hash_password(password),
            'telefono': telefono,
            'fecha_creacion': datetime.now().isoformat(),
            'activo': True
        }
        
        table.put_item(Item=usuario_item)
        
        usuario_respuesta = {
            'tenant_id': tenant_id,
            'email': email,
            'nombre': nombre,
            'telefono': telefono,
            'fecha_creacion': usuario_item['fecha_creacion'],
            'activo': True
        }
        
        return lambda_response(201, {
            'message': 'Usuario creado exitosamente',
            'usuario': usuario_respuesta
        })
        
    except json.JSONDecodeError:
        return lambda_response(400, {'error': 'JSON inválido'})
    except Exception as e:
        print(f"Error creando usuario: {str(e)}")
        return lambda_response(500, {'error': 'Error interno del servidor'})

def login_usuario(event, context):
    """Función para login de usuario y generación de token"""
    try:
        body = event['body']
        if isinstance(body, str):
            body = json.loads(body)
        
        required_fields = ['tenant_id', 'email', 'password']
        for field in required_fields:
            if field not in body or not body[field]:
                return lambda_response(400, {
                    'error': f'Campo requerido: {field}'
                })
        
        tenant_id = body['tenant_id']
        email = body['email']
        password = body['password']
        
        try:
            response = table.get_item(
                Key={
                    'tenant_id': tenant_id,
                    'email': email
                }
            )
            
            if 'Item' not in response:
                return lambda_response(401, {
                    'error': 'Credenciales inválidas'
                })
            
            usuario = response['Item']
            
            if usuario['password'] != hash_password(password):
                return lambda_response(401, {
                    'error': 'Credenciales inválidas'
                })
            
            if not usuario.get('activo', True):
                return lambda_response(401, {
                    'error': 'Usuario inactivo'
                })
            
        except Exception as e:
            print(f"Error buscando usuario: {str(e)}")
            return lambda_response(500, {'error': 'Error interno del servidor'})
        
        payload = {
            'tenant_id': tenant_id,
            'email': email,
            'nombre': usuario['nombre'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=1),
            'iat': datetime.now(timezone.utc)
        }
        
        token = pyjwt.encode(payload, jwt_secret, algorithm='HS256')
        
        return lambda_response(200, {
            'message': 'Login exitoso',
            'token': token,
            'usuario': {
                'tenant_id': tenant_id,
                'email': email,
                'nombre': usuario['nombre'],
                'telefono': usuario.get('telefono', '')
            }
        })
        
    except json.JSONDecodeError:
        return lambda_response(400, {'error': 'JSON inválido'})
    except Exception as e:
        print(f"Error en login: {str(e)}")
        return lambda_response(500, {'error': 'Error interno del servidor'})

def validar_token(event, context):
    """Función para validar token JWT"""
    try:
        token = None
        
        if 'headers' in event and event['headers']:
            auth_header = event['headers'].get('Authorization') or event['headers'].get('authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token and event.get('body'):
            body = event['body']
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except json.JSONDecodeError:
                    body = {}
            token = body.get('token')
        
        if not token:
            return lambda_response(400, {
                'error': 'Token requerido'
            })
        
        try:
            payload = pyjwt.decode(token, jwt_secret, algorithms=['HS256'])
            
            return lambda_response(200, {
                'valid': True,
                'usuario': {
                    'tenant_id': payload['tenant_id'],
                    'email': payload['email'],
                    'nombre': payload['nombre']
                },
                'expires_at': payload['exp']
            })
            
        except pyjwt.ExpiredSignatureError:
            return lambda_response(401, {
                'valid': False,
                'error': 'Token expirado'
            })
        except pyjwt.InvalidTokenError:
            return lambda_response(401, {
                'valid': False,
                'error': 'Token inválido'
            })
        
    except Exception as e:
        print(f"Error validando token: {str(e)}")
        return lambda_response(500, {'error': 'Error interno del servidor'})
