CREATE TABLE IF NOT EXISTS "tickets" (
	"ID"	INTEGER NOT NULL UNIQUE,
	"Creator"	INTEGER NOT NULL,
	"Title"	TEXT NOT NULL,
	"Description"	TEXT,
	"State"	TEXT NOT NULL,
	PRIMARY KEY("ID" AUTOINCREMENT),
	FOREIGN KEY("Creator") REFERENCES "users"("ID")
);