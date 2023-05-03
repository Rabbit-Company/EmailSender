CREATE TABLE accounts (
	username TEXT PRIMARY KEY,
	password TEXT NOT NULL,
	email TEXT NOT NULL,
	max_domains INTEGER NOT NULL DEFAULT 1,
	max_emails INTEGER NOT NULL DEFAULT 3,
	max_sent INTEGER NOT NULL DEFAULT 500,
	created TEXT NOT NULL,
	accessed TEXT NOT NULL
);

CREATE TABLE emails (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	owner TEXT NOT NULL,
	email TEXT NOT NULL,
	name TEXT NOT NULL,
	sent INTEGER NOT NULL DEFAULT 0,
	secret_token TEXT NOT NULL,
	created TEXT NOT NULL,
	updated TEXT NOT NULL,
	UNIQUE(email)
);

CREATE TABLE domains (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	owner TEXT NOT NULL,
	domain TEXT NOT NULL,
	selector TEXT NOT NULL DEFAULT "mcdkim",
	private_key TEXT NOT NULL,
	created TEXT NOT NULL,
	updated TEXT NOT NULL,
	UNIQUE(domain)
);