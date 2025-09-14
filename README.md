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
