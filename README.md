# Express backend

Install dependencies with `npm install`. Copy `.env.example` to `.env`, set
`MONGODB_URI` to your MongoDB connection string, and replace `JWT_SECRET` with
a random secret of at least 32 bytes. Then start the server with `npm start`.
For development with automatic restarts, use `npm run dev`.

The server listens on port `3000` by default. Set `PORT` to use a different
port and `FRONTEND_ORIGIN` to configure the browser client's allowed origin.

## Authentication

- `POST /register` accepts `{ "username", "email", "password" }`.
- `POST /login` accepts `{ "email", "password" }`.

Both endpoints return a one-hour JWT and the user's public profile. Passwords
must be at least 8 characters and no more than 72 UTF-8 bytes.
