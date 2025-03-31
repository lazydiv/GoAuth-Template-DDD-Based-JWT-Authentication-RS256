# GoAuth-Template-DDD-Based-JWT-Authentication-RS256

This repository provides a Go-based authentication template using Gin & JWT (RS256). It is structured with Domain-Driven Design (DDD) principles to offer a ready-to-use authentication system with short-lived access tokens and refresh tokens.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [License](#license)

## Features
- JWT-based authentication using RS256 algorithm.
- Domain-Driven Design (DDD) architecture.
- Short-lived access tokens and long-lived refresh tokens.
- Middleware for authentication and authorization.
- Easy to extend and customize.

## Prerequisites
- [Go](https://golang.org/dl/) 1.16 or higher
- [Gin](https://github.com/gin-gonic/gin)
- [JWT](https://github.com/dgrijalva/jwt-go)

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/lazydiv/GoAuth-Template-DDD-Based-JWT-Authentication-RS256.git
    cd GoAuth-Template-DDD-Based-JWT-Authentication-RS256
    ```

2. Install dependencies:
    ```sh
    go mod tidy
    ```

## Usage
1. Generate RSA keys for JWT:
    ```sh
    openssl genrsa -out app.rsa 2048
    openssl rsa -in app.rsa -pubout > app.rsa.pub
    ```

2. Copy the generated keys to the `keys` directory.

3. Run the application:
    ```sh
    go run main.go
    ```

## Project Structure
```
.
├── app                  # Application layer
├── domain               # Domain layer
├── infrastructure       # Infrastructure layer
├── interfaces           # Interfaces layer
├── main.go              # Entry point
└── keys                 # RSA keys for JWT
```

## Configuration
Configuration settings can be found in the `config` directory. Modify the `config.yaml` file to suit your environment.

## Endpoints
- `POST /login` - Authenticate user and return access and refresh tokens.
- `POST /refresh` - Refresh access token using refresh token.
- `GET /protected` - Access a protected route (requires valid access token).

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
