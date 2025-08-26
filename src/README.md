# AuthServer.API

AuthServer.API is a modern, modular authentication and authorization API built with ASP.NET Core. It provides secure user authentication, token issuance, and OAuth2 flows for your applications and services.

## Project Structure

```
src/
  AuthServer.API/           # Main API project (controllers, startup, config)
  AuthServer.Application/   # Application layer (CQRS, business logic)
  AuthServer.Domain/        # Domain models and interfaces
  AuthServer.Infrastructure/# Data access, persistence, external services
```

## How It Works

### 1. Authentication & Token Issuance
- **Login:**
  - `POST /api/auth/login` — Accepts username and password, returns user info and tokens if valid.
- **Register:**
  - `POST /api/auth/register` — Accepts registration details, creates a new user, returns user info and tokens.
- **Token:**
  - `POST /api/oauth/token` — Accepts OAuth2 token requests (password, refresh_token, etc.), returns JWT access and refresh tokens.
- **Revoke Token:**
  - `POST /api/oauth/revoke` — Revokes a refresh token (implementation stubbed in code).

### 2. Security
- Uses JWT Bearer authentication for all protected endpoints.
- JWT settings (secret, issuer, audience, lifetimes) are configured in `appsettings.Development.json`.
- Role-based and permission-based policies are enforced (e.g., `AdminOnly`, `CanReadUsers`).
- CORS is enabled for frontend development (localhost:3000, 5173).

### 3. API Documentation
- Swagger UI is enabled in development for easy API exploration and testing.

### 4. Database
- Uses Entity Framework Core for data access.
- On startup, the database is created and seeded with default data if needed.

## Example Usage

### Login
```http
POST /api/auth/login
Content-Type: application/json
{
  "username": "user@example.com",
  "password": "yourpassword"
}
```

### Register
```http
POST /api/auth/register
Content-Type: application/json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "yourpassword",
  "firstName": "New",
  "lastName": "User"
}
```

### Get Token (OAuth2)
```http
POST /api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user@example.com&password=yourpassword&client_id=yourclientid
```

## Key Files
- `Program.cs` — Configures services, authentication, authorization, Swagger, and database seeding.
- `Controllers/` — Contains API endpoints for authentication and OAuth2.
- `Models/DTOs.cs` — Request/response models for API endpoints.
- `appsettings.Development.json` — Configuration for JWT, database, logging, etc.

## Running the API
1. Ensure you have .NET 7+ and SQL Server (or LocalDB) installed.
2. Update connection strings and JWT settings as needed in `appsettings.Development.json`.
3. From the `src/AuthServer.API` directory, run:
   ```sh
   dotnet run
   ```
4. Visit Swagger UI at `https://localhost:5001/swagger` (or the port in your launch settings).

## Security Notes
- Use a strong, unique JWT secret in production.
- Always use HTTPS in production.
- Review and adjust CORS settings before deploying.

---

For more details, see the code in each layer and the Swagger UI for live API docs.
