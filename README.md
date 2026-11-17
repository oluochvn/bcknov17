# Express backend

Install dependencies with `npm install`. Set `MONGODB_URI` to your MongoDB
connection string in your `.env` file. Then start the server with `npm start`.
For development with automatic restarts, use `npm run dev`.

The server listens on port `3000` by default. Set `PORT` to use a different
port.

## Authentication

- `POST /register` accepts `{ "username", "email", "password" }`.
- `POST /login` accepts `{ "email", "password" }`.

Both endpoints return the user's public profile. Passwords must be at least 8
characters and no more than 72 UTF-8 bytes. No token or session is issued.
