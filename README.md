# API Usuarios - Microservicio Multi-tenant

Este microservicio maneja la autenticación y gestión de usuarios con soporte multi-tenant usando AWS Lambda, DynamoDB y JWT.

## Características

- ✅ Multi-tenancy (soporte para múltiples inquilinos)
- ✅ Serverless con AWS Lambda
- ✅ Autenticación JWT con expiración de 1 hora
- ✅ Hash seguro de contraseñas
- ✅ CORS habilitado
- ✅ Despliegue automatizado con Serverless Framework

## Endpoints

### 1. Crear Usuario
- **URL**: `POST /usuarios/crear`
- **Descripción**: Crea un nuevo usuario en el sistema
- **Body**:
```json
{
  "tenant_id": "empresa1",
  "nombre": "Juan Pérez",
  "email": "juan@email.com", 
  "password": "mipassword123",
  "telefono": "+51987654321"
}
```

### 2. Login Usuario
- **URL**: `POST /usuarios/login`
- **Descripción**: Autentica usuario y devuelve token JWT
- **Body**:
```json
{
  "tenant_id": "empresa1",
  "email": "juan@email.com",
  "password": "mipassword123"
}
```
- **Respuesta**:
```json
{
  "message": "Login exitoso",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "usuario": {
    "tenant_id": "empresa1",
    "email": "juan@email.com",
    "nombre": "Juan Pérez",
    "telefono": "+51987654321"
  }
}
```

### 3. Validar Token
- **URL**: `POST /usuarios/validar`
- **Descripción**: Valida token JWT
- **Headers**: `Authorization: Bearer <token>` O
- **Body**:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

## Instalación y Despliegue

### Prerrequisitos
- Node.js 18+
- Python 3.12+
- AWS CLI configurado
- Serverless Framework

### Comandos de Despliegue

```bash
# Instalar dependencias
npm install

# Desplegar a desarrollo
npm run deploy-dev

# Desplegar a testing
npm run deploy-test

# Desplegar a producción
npm run deploy-prod

# Ver información del despliegue
npm run info

# Ver logs de una función
npm run logs crear-usuario
```

## Estructura del Proyecto

```
api-usuarios/
├── usuarios.py          # Funciones Lambda
├── serverless.yml       # Configuración Serverless
├── requirements.txt     # Dependencias Python
├── package.json        # Configuración del proyecto
└── README.md           # Documentación
```

## Variables de Entorno

- `TABLE_NAME`: Nombre de la tabla DynamoDB (auto-generado por stage)
- `JWT_SECRET`: Secreto para firmar tokens JWT

## Tabla DynamoDB

**Nombre**: `{stage}-t_usuarios`

**Schema**:
- **Partition Key**: `tenant_id` (String)
- **Sort Key**: `email` (String)

**Campos**:
- `tenant_id`: Identificador del inquilino
- `email`: Email del usuario (único por tenant)
- `nombre`: Nombre completo
- `password`: Password hasheado (SHA256)
- `telefono`: Teléfono opcional
- `fecha_creacion`: Timestamp de creación
- `activo`: Estado del usuario

## Seguridad

- Las contraseñas se hashean con SHA256
- Los tokens JWT expiran en 1 hora
- Soporte CORS para frontend
- Validación de campos requeridos
- Multi-tenancy para aislamiento de datos

## Testing

### Crear Usuario
```bash
curl -X POST https://tu-api-url/usuarios/crear \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "empresa1",
    "nombre": "Juan Pérez",
    "email": "juan@email.com",
    "password": "mipassword123"
  }'
```

### Login
```bash
curl -X POST https://tu-api-url/usuarios/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "empresa1", 
    "email": "juan@email.com",
    "password": "mipassword123"
  }'
```

### Validar Token
```bash
curl -X POST https://tu-api-url/usuarios/validar \
  -H "Authorization: Bearer <tu-token-jwt>"
```