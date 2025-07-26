# DotNetJwtAuth

A secure ASP.NET Core Web API project with JWT authentication, refresh token support, and role-based authorization.

# JwtAuthApi

A secure ASP.NET Core Web API with JWT authentication and refresh token support. This project demonstrates how to implement user registration, login, JWT token generation, token refresh, and protected routes using .NET 6 or later.

---

## 🚀 Features

- ✅ User Registration
- ✅ User Login with JWT Access Token
- ✅ Secure Refresh Token Mechanism
- ✅ Role-Based Authorization
- ✅ Protected API Endpoints
- ✅ ASP.NET Core Identity-style Password Hashing
- ✅ EF Core with SQL Server
- ✅ Swagger API Documentation

---

## 📁 Project Structure

first_code_JWT/
│
├── Controllers/
│ └── AuthController.cs
│
├── Services/
│ ├── IJwtTokenService.cs
│ └── JwtTokenService.cs
│
├── DTOs/
│ ├── RegisterUserDto.cs
│ ├── LoginRequest.cs
│ └── RefreshTokenRequest.cs
│
├── Models/
│ └── User.cs
│
├── Data/
│ └── AppDbContext.cs
│
├── Settings/
│ └── JwtSettings.cs
│
├── Program.cs
└── appsettings.json

📦 Technologies Used
ASP.NET Core Web API

Entity Framework Core (EF Core)

SQL Server

JWT (JSON Web Token)

ASP.NET Identity PasswordHasher

Swagger / Swashbuckle
