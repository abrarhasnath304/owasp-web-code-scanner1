# OWASP Scanner Backend

This is the backend service for the OWASP Web Security Scanner application.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory with the following content:
```
PORT=3000
NODE_ENV=development
```

3. Start the development server:
```bash
npm run dev
```

## API Endpoints

### Health Check
- GET `/api/health`
- Returns the server status

### Security Scan
- POST `/api/scan`
- Body: `{ "url": "https://example.com" }`
- Initiates a security scan for the provided URL

## Development

The server uses:
- Express.js for the web server
- Helmet for security headers
- CORS for cross-origin requests
- dotenv for environment variables

## Security Features

- Helmet.js for secure HTTP headers
- CORS protection
- Input validation
- Error handling 