# Final Project Frontend

Task management frontend application.

## Architecture

This frontend is served by **Nginx**, which also acts as a reverse proxy for API requests.

- **Frontend Static Files**: Root path `/`
- **Backend API**: Proxied through `/api` to the backend service.

## Local Development

To run the application locally for development:

1.  Ensure you have Node.js installed.
2.  Install dependencies: `npm install`
3.  Start the development server: `npm start`

The development server is configured to proxy API requests to `http://localhost:5000` via the `proxy` setting in `package.json`.

## Production

The production image is built using a multi-stage Docker build:
1.  **Build Stage**: Compiles the React application.
2.  **Runtime Stage**: Nginx serves the compiled files and handles API proxying.
