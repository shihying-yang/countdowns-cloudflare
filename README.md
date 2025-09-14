# Countdowns Cloudflare Worker

A simple, self-contained countdown timer application built to run on Cloudflare Workers. It uses Cloudflare D1 for data storage and has no other external dependencies.

## Features

-   **User Authentication**: Secure sign-up and login for managing personal countdowns.
-   **Password Security**: Passwords are not stored in plaintext. They are hashed using PBKDF2-SHA256 with a unique salt for each user.
-   **Session Management**: Cookie-based sessions with idle and absolute timeouts.
-   **Countdown Management**: Create, list, update, and delete countdowns.
-   **Flexible Timestamps**: Supports both date-only (e.g., "days until X") and full date-time countdowns.
-   **Public Sharing**: Generate a unique, revocable link to share your countdowns page with others.
-   **Security**: Includes rate limiting and login attempt lockouts to prevent abuse.
-   **Self-Contained UI**: A minimal, functional user interface is served directly from the worker, requiring no separate front-end hosting.

## Tech Stack

-   **Runtime**: [Cloudflare Workers](https://workers.cloudflare.com/)
-   **Database**: [Cloudflare D1](https://developers.cloudflare.com/d1/)
-   **Dependencies**: Zero runtime dependencies.

## Getting Started

### Prerequisites

-   A Cloudflare account.
-   [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/) installed.
-   [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed and configured (`npm install -g wrangler`).

### Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd countdowns-cloudflare
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Configure Wrangler:**
    If you don't have one, create a `wrangler.toml` file and configure it with your account ID.

4.  **Create D1 Database:**
    Run the following commands to create the database and the necessary tables.
    ```bash
    # Create the database
    wrangler d1 create countdowns-db
    ```

    Then, add the binding to your `wrangler.toml`:
    ```toml
    [[d1_databases]]
    binding = "DB"
    database_name = "countdowns-db"
    database_id = "<your-database-id>"
    ```

    Finally, execute the schema below. I'd recommend saving this as `schema.sql` and running it with `wrangler d1 execute countdowns-db --file=./schema.sql`.

    ```sql
    -- Inferred from src/index.js
    CREATE TABLE users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      email_verified INTEGER NOT NULL DEFAULT 0,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_algo TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      updated_at INTEGER DEFAULT (unixepoch())
    );
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      idle_expires INTEGER NOT NULL,
      active_expires INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE countdowns (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      stamp TEXT NOT NULL,
      date_only INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch()),
      updated_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE shares_pages (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      expires_at INTEGER,
      revoked_at INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE rl_attempts (
      key TEXT NOT NULL,
      ts INTEGER NOT NULL
    );
    CREATE INDEX idx_rl_attempts_key_ts ON rl_attempts (key, ts);
    CREATE TABLE login_lockouts (
      email TEXT PRIMARY KEY,
      until INTEGER NOT NULL
    );
    ```

5.  **Run locally:**
    ```bash
    wrangler dev
    ```
    The application will be available at `http://localhost:8787`.

6.  **Deploy:**
    ```bash
    wrangler deploy
    ```

## Future Improvements (TODO)

This is a list of potential improvements to enhance the project's maintainability, robustness, and feature set.

- [x]  **Separate Frontend Assets**:
    -   **What**: Move the embedded HTML, CSS, and client-side JavaScript into their own static files (`public/index.html`, `public/style.css`, etc.).
    -   **Why**: Improves code organization, enables better tooling (syntax highlighting, linting), and separates backend logic from frontend presentation.

- [ ]  **Add Robust Input Validation**:
    -   **What**: Use a library like Zod to define and enforce schemas for all API request bodies.
    -   **Why**: Centralizes validation, prevents bad data from reaching business logic, and provides clearer error messages.

- [ ]  **Centralize API Routing**:
    -   **What**: Replace the `if/else if` routing structure with a dedicated router like itty-router or Hono.
    -   **Why**: Makes API endpoint definitions cleaner, more declarative, and easier to manage as the application grows.

- [ ]  **Implement Database Migrations**:
    -   **What**: Use Wrangler's official D1 migrations feature to manage database schema changes.
    -   **Why**: Allows for version-controlled, automated, and safe evolution of the database schema over time.

- [ ]  **Add a Testing Suite**:
    -   **What**: Implement unit tests for helper functions and integration tests for API endpoints using a framework like Vitest.
    -   **Why**: Ensures code correctness, prevents regressions, and gives confidence when refactoring or adding new features.

- [ ]  **Externalize Configuration**:
    -   **What**: Move hardcoded constants (e.g., cookie durations, rate limits) into the `wrangler.toml` file or a `.dev.vars` file for local development.
    -   **Why**: Allows for easy configuration changes between different environments (development, production) without modifying code.

- [ ]  **Harden Timezone Handling**:
    -   **What**: Ensure all timestamps are consistently handled in UTC. When a user inputs a time, convert it from their local timezone to UTC on the client before sending it to the server. Store all timestamps in the database as UTC (e.g., using the ISO 8601 format with a `Z` suffix).
    -   **Why**: The current implementation can lead to incorrect countdowns for users in different timezones. Storing everything in UTC prevents ambiguity and ensures that countdowns are accurate regardless of where the user or viewers are in the world.

## User Experience & Feature Enhancements (TODO)

- [ ]  **Improve API Error Messages**:
    -   **What**: Map cryptic backend error codes like `INVALID_CREDENTIALS` and `EMAIL_IN_USE` to more user-friendly messages on the frontend (e.g., "Invalid email or password.", "An account with this email already exists.").
    -   **Why**: Provides a better user experience by giving clear, actionable feedback when something goes wrong.

- [ ]  **Implement Password Reset**:
    -   **What**: Add a "Forgot Password" flow. This typically involves generating a secure, single-use token, sending it to the user's email, and providing a page where they can set a new password.
    -   **Why**: A critical feature for any application with user accounts.

- [ ]  **Create Admin Functionality**:
    -   **What**: Introduce an "admin" role for users. An admin could have the ability to view all users, reset passwords, or delete user accounts.
    -   **Why**: Useful for application management and user support.
    -   **Note**: The database schema is already correctly configured with `ON DELETE CASCADE`, so deleting a user from the `users` table will automatically remove all of their associated countdowns, sessions, and share links.
